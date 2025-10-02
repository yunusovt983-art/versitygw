// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3err"
)

func VerifyObjectCopyAccess(ctx context.Context, be backend.Backend, copySource string, opts AccessOptions) error {
	if opts.IsRoot {
		return nil
	}
	if opts.Acc.Role == RoleAdmin {
		return nil
	}

	// Verify destination bucket access
	if err := VerifyAccess(ctx, be, opts); err != nil {
		return err
	}
	// Verify source bucket access
	srcBucket, srcObject, found := strings.Cut(copySource, "/")
	if !found {
		return s3err.GetAPIError(s3err.ErrInvalidCopySource)
	}

	// Get source bucket ACL
	srcBucketACLBytes, err := be.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: &srcBucket})
	if err != nil {
		return err
	}

	var srcBucketAcl ACL
	if err := json.Unmarshal(srcBucketACLBytes, &srcBucketAcl); err != nil {
		return err
	}

	if err := VerifyAccess(ctx, be, AccessOptions{
		Acl:           srcBucketAcl,
		AclPermission: PermissionRead,
		IsRoot:        opts.IsRoot,
		Acc:           opts.Acc,
		Bucket:        srcBucket,
		Object:        srcObject,
		Action:        GetObjectAction,
	}); err != nil {
		return err
	}

	return nil
}

type AccessOptions struct {
	Acl            ACL
	AclPermission  Permission
	IsRoot         bool
	Acc            Account
	Bucket         string
	Object         string
	Action         Action
	Readonly       bool
	IsBucketPublic bool
	RoleManager    RoleManager // Optional: for enhanced role-based access control
}

func VerifyAccess(ctx context.Context, be backend.Backend, opts AccessOptions) error {
	// Skip the access check for public buckets
	if opts.IsBucketPublic {
		return nil
	}
	if opts.Readonly {
		if opts.AclPermission == PermissionWrite || opts.AclPermission == PermissionWriteAcp {
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
	}
	if opts.IsRoot {
		return nil
	}
	if opts.Acc.Role == RoleAdmin {
		return nil
	}

	// Try enhanced role-based access control first if RoleManager is available
	if opts.RoleManager != nil {
		allowed, err := verifyEnhancedRoleAccessWithAggregation(opts.RoleManager, opts.Acc.Access, opts.Bucket, opts.Object, opts.Action)
		if err != nil {
			// Log the error but continue with fallback methods
			// In production, you might want to handle this differently
		} else {
			if allowed {
				return nil
			}
			// If explicitly denied by enhanced roles, return access denied
			return s3err.GetAPIError(s3err.ErrAccessDenied)
		}
		// If enhanced role check fails, fall back to traditional methods
	}

	policy, policyErr := be.GetBucketPolicy(ctx, opts.Bucket)
	if policyErr != nil {
		if !errors.Is(policyErr, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
			return policyErr
		}
	} else {
		return VerifyBucketPolicy(policy, opts.Acc.Access, opts.Bucket, opts.Object, opts.Action)
	}

	if err := verifyACL(opts.Acl, opts.Acc.Access, opts.AclPermission); err != nil {
		return err
	}

	return nil
}

// Detects if the action is policy related
// e.g.
// 'GetBucketPolicy', 'PutBucketPolicy'
func isPolicyAction(action Action) bool {
	return action == GetBucketPolicyAction || action == PutBucketPolicyAction
}

// VerifyPublicAccess checks if the bucket is publically accessible by ACL or Policy
func VerifyPublicAccess(ctx context.Context, be backend.Backend, action Action, permission Permission, bucket, object string) error {
	// ACL disabled
	policy, err := be.GetBucketPolicy(ctx, bucket)
	if err != nil && !errors.Is(err, s3err.GetAPIError(s3err.ErrNoSuchBucketPolicy)) {
		return err
	}
	if err == nil {
		err = VerifyPublicBucketPolicy(policy, bucket, object, action)
		if err == nil {
			// if ACLs are disabled, and the bucket grants public access,
			// policy actions should return 'MethodNotAllowed'
			if isPolicyAction(action) {
				return s3err.GetAPIError(s3err.ErrMethodNotAllowed)
			}

			return nil
		}
	}

	// if the action is not in the ACL whitelist the access is denied
	_, ok := publicACLAllowedActions[action]
	if !ok {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	err = VerifyPublicBucketACL(ctx, be, bucket, action, permission)
	if err != nil {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}

func MayCreateBucket(acct Account, isRoot bool) error {
	if isRoot {
		return nil
	}

	if acct.Role == RoleUser {
		return s3err.GetAPIError(s3err.ErrAccessDenied)
	}

	return nil
}

func IsAdminOrOwner(acct Account, isRoot bool, acl ACL) error {
	// Owner check
	if acct.Access == acl.Owner {
		return nil
	}

	// Root user has access over almost everything
	if isRoot {
		return nil
	}

	// Admin user case
	if acct.Role == RoleAdmin {
		return nil
	}

	// Return access denied in all other cases
	return s3err.GetAPIError(s3err.ErrAccessDenied)
}

type PublicACLAllowedActions map[Action]struct{}

var publicACLAllowedActions PublicACLAllowedActions = PublicACLAllowedActions{
	ListBucketAction:                 struct{}{},
	PutObjectAction:                  struct{}{},
	ListBucketMultipartUploadsAction: struct{}{},
	DeleteObjectAction:               struct{}{},
	ListBucketVersionsAction:         struct{}{},
	GetObjectAction:                  struct{}{},
	GetObjectAttributesAction:        struct{}{},
	GetObjectAclAction:               struct{}{},
}

// verifyEnhancedRoleAccess checks access using the enhanced role-based permission system
func verifyEnhancedRoleAccess(roleManager RoleManager, userID, bucket, object string, action Action) (bool, error) {
	// Build resource ARN
	resource := buildResourceARN(bucket, object)
	
	// Convert Action to string format expected by enhanced roles
	actionStr := string(action)
	
	// Check permission using role manager
	allowed, err := roleManager.CheckPermission(userID, resource, actionStr)
	if err != nil {
		return false, fmt.Errorf("failed to check enhanced role permission: %w", err)
	}
	
	return allowed, nil
}

// verifyEnhancedRoleAccessWithAggregation checks access using enhanced roles with proper permission aggregation
func verifyEnhancedRoleAccessWithAggregation(roleManager RoleManager, userID, bucket, object string, action Action) (bool, error) {
	// Get effective permissions (includes role hierarchy)
	effectivePermissions, err := roleManager.GetEffectivePermissions(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get effective permissions: %w", err)
	}
	
	if effectivePermissions == nil || len(effectivePermissions.Permissions) == 0 {
		return false, nil // No permissions, no access
	}
	
	// Build resource ARN
	resource := buildResourceARN(bucket, object)
	
	// Check if the effective permissions allow the action
	return effectivePermissions.HasPermission(resource, string(action)), nil
}

// buildResourceARN constructs an ARN-like resource identifier for permission checking
func buildResourceARN(bucket, object string) string {
	if object == "" {
		return fmt.Sprintf("arn:aws:s3:::%s", bucket)
	}
	return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, object)
}

// VerifyAccessWithRoles is an enhanced version of VerifyAccess that uses role-based permissions
func VerifyAccessWithRoles(ctx context.Context, be backend.Backend, roleManager RoleManager, opts AccessOptions) error {
	// Set the role manager in options
	opts.RoleManager = roleManager
	return VerifyAccess(ctx, be, opts)
}

// GetEffectivePermissionsForUser returns the effective permissions for a user
func GetEffectivePermissionsForUser(roleManager RoleManager, userID string) (*PermissionSet, error) {
	if roleManager == nil {
		return nil, fmt.Errorf("role manager is required")
	}
	
	return roleManager.GetEffectivePermissions(userID)
}

// CheckUserPermission is a convenience function to check if a user has a specific permission
func CheckUserPermission(roleManager RoleManager, userID, bucket, object string, action Action) (bool, error) {
	if roleManager == nil {
		return false, fmt.Errorf("role manager is required")
	}
	
	resource := buildResourceARN(bucket, object)
	return roleManager.CheckPermission(userID, resource, string(action))
}

// AggregatePermissionsFromRoles aggregates permissions from multiple roles using union semantics
func AggregatePermissionsFromRoles(roles []*EnhancedRole) *PermissionSet {
	return ComputeEffectivePermissions(roles)
}

// ValidateAccessWithMultipleRoles validates access when a user has multiple roles
func ValidateAccessWithMultipleRoles(roles []*EnhancedRole, bucket, object string, action Action) bool {
	if len(roles) == 0 {
		return false // No roles, no access
	}
	
	// Compute effective permissions from all roles
	effectivePermissions := ComputeEffectivePermissions(roles)
	
	// Build resource ARN
	resource := buildResourceARN(bucket, object)
	
	// Check if the effective permissions allow the action
	return effectivePermissions.HasPermission(resource, string(action))
}

// EnhancedAccessChecker provides a comprehensive access checking interface
type EnhancedAccessChecker struct {
	roleManager RoleManager
	backend     backend.Backend
}

// NewEnhancedAccessChecker creates a new enhanced access checker
func NewEnhancedAccessChecker(roleManager RoleManager, backend backend.Backend) *EnhancedAccessChecker {
	return &EnhancedAccessChecker{
		roleManager: roleManager,
		backend:     backend,
	}
}

// CheckAccess performs comprehensive access checking using enhanced roles
func (eac *EnhancedAccessChecker) CheckAccess(ctx context.Context, opts AccessOptions) error {
	opts.RoleManager = eac.roleManager
	return VerifyAccess(ctx, eac.backend, opts)
}

// GetUserPermissions returns all effective permissions for a user
func (eac *EnhancedAccessChecker) GetUserPermissions(userID string) (*PermissionSet, error) {
	return eac.roleManager.GetEffectivePermissions(userID)
}

// CheckSpecificPermission checks a specific permission for a user
func (eac *EnhancedAccessChecker) CheckSpecificPermission(userID, bucket, object string, action Action) (bool, error) {
	resource := buildResourceARN(bucket, object)
	return eac.roleManager.CheckPermission(userID, resource, string(action))
}

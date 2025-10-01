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

package ipfs

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// NewConfigAPIServer creates a new configuration API server
func NewConfigAPIServer(configManager *ConfigManager, port int, logger *log.Logger) *ConfigAPIServer {
	return &ConfigAPIServer{
		configManager: configManager,
		port:          port,
		logger:        logger,
	}
}

// Start starts the configuration API server
func (s *ConfigAPIServer) Start() error {
	mux := http.NewServeMux()
	
	// Configuration endpoints
	mux.HandleFunc("/api/v1/config", s.handleConfig)
	mux.HandleFunc("/api/v1/config/validate", s.handleValidateConfig)
	mux.HandleFunc("/api/v1/config/reload", s.handleReloadConfig)
	mux.HandleFunc("/api/v1/config/save", s.handleSaveConfig)
	
	// Health check endpoint
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	
	// Configuration field endpoints
	mux.HandleFunc("/api/v1/config/cluster-endpoints", s.handleClusterEndpoints)
	mux.HandleFunc("/api/v1/config/replication", s.handleReplication)
	mux.HandleFunc("/api/v1/config/timeouts", s.handleTimeouts)
	mux.HandleFunc("/api/v1/config/performance", s.handlePerformance)
	mux.HandleFunc("/api/v1/config/cache", s.handleCache)
	mux.HandleFunc("/api/v1/config/metadata", s.handleMetadata)
	mux.HandleFunc("/api/v1/config/replica-manager", s.handleReplicaManager)
	
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      s.corsMiddleware(s.loggingMiddleware(mux)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	go func() {
		s.logger.Printf("Configuration API server starting on port %d", s.port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("Configuration API server error: %v", err)
		}
	}()
	
	return nil
}

// Stop stops the configuration API server
func (s *ConfigAPIServer) Stop() error {
	if s.server == nil {
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	s.logger.Println("Stopping configuration API server...")
	return s.server.Shutdown(ctx)
}

// handleConfig handles GET/PUT requests for the entire configuration
func (s *ConfigAPIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetConfig(w, r)
	case http.MethodPut:
		s.handleUpdateConfig(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleGetConfig handles GET requests for configuration
func (s *ConfigAPIServer) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	s.writeJSON(w, http.StatusOK, config)
}

// handleUpdateConfig handles PUT requests for configuration
func (s *ConfigAPIServer) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config IPFSConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	if err := s.configManager.UpdateConfig(&config); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Configuration update failed: %v", err))
		return
	}
	
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Configuration updated"})
}

// handleValidateConfig handles POST requests for configuration validation
func (s *ConfigAPIServer) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	var config IPFSConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
		return
	}
	
	result := s.configManager.ValidateConfig(&config)
	s.writeJSON(w, http.StatusOK, result)
}

// handleReloadConfig handles POST requests for configuration reload
func (s *ConfigAPIServer) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	if err := s.configManager.ReloadConfig(); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Configuration reload failed: %v", err))
		return
	}
	
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Configuration reloaded"})
}

// handleSaveConfig handles POST requests for configuration save
func (s *ConfigAPIServer) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	if err := s.configManager.SaveConfig(); err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Configuration save failed: %v", err))
		return
	}
	
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Configuration saved"})
}

// handleHealth handles GET requests for health check
func (s *ConfigAPIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}
	
	s.writeJSON(w, http.StatusOK, health)
}

// handleClusterEndpoints handles cluster endpoints configuration
func (s *ConfigAPIServer) handleClusterEndpoints(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"cluster_endpoints": config.ClusterEndpoints,
		})
		
	case http.MethodPut:
		var req struct {
			ClusterEndpoints []string `json:"cluster_endpoints"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		newConfig.ClusterEndpoints = req.ClusterEndpoints
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleReplication handles replication configuration
func (s *ConfigAPIServer) handleReplication(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"replication_min": config.ReplicationMin,
			"replication_max": config.ReplicationMax,
		})
		
	case http.MethodPut:
		var req struct {
			ReplicationMin int `json:"replication_min"`
			ReplicationMax int `json:"replication_max"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		if req.ReplicationMin > 0 {
			newConfig.ReplicationMin = req.ReplicationMin
		}
		if req.ReplicationMax > 0 {
			newConfig.ReplicationMax = req.ReplicationMax
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleTimeouts handles timeout configuration
func (s *ConfigAPIServer) handleTimeouts(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"connect_timeout": config.ConnectTimeout.String(),
			"request_timeout": config.RequestTimeout.String(),
			"pin_timeout":     config.PinTimeout.String(),
		})
		
	case http.MethodPut:
		var req struct {
			ConnectTimeout string `json:"connect_timeout,omitempty"`
			RequestTimeout string `json:"request_timeout,omitempty"`
			PinTimeout     string `json:"pin_timeout,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		
		if req.ConnectTimeout != "" {
			if d, err := time.ParseDuration(req.ConnectTimeout); err == nil {
				newConfig.ConnectTimeout = d
			} else {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid connect_timeout: %v", err))
				return
			}
		}
		
		if req.RequestTimeout != "" {
			if d, err := time.ParseDuration(req.RequestTimeout); err == nil {
				newConfig.RequestTimeout = d
			} else {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid request_timeout: %v", err))
				return
			}
		}
		
		if req.PinTimeout != "" {
			if d, err := time.ParseDuration(req.PinTimeout); err == nil {
				newConfig.PinTimeout = d
			} else {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid pin_timeout: %v", err))
				return
			}
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handlePerformance handles performance configuration
func (s *ConfigAPIServer) handlePerformance(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"max_concurrent_pins": config.MaxConcurrentPins,
			"chunk_size":          config.ChunkSize,
			"compression_enabled": config.CompressionEnabled,
			"max_retries":         config.MaxRetries,
		})
		
	case http.MethodPut:
		var req struct {
			MaxConcurrentPins  *int   `json:"max_concurrent_pins,omitempty"`
			ChunkSize          *int64 `json:"chunk_size,omitempty"`
			CompressionEnabled *bool  `json:"compression_enabled,omitempty"`
			MaxRetries         *int   `json:"max_retries,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		
		if req.MaxConcurrentPins != nil {
			newConfig.MaxConcurrentPins = *req.MaxConcurrentPins
		}
		if req.ChunkSize != nil {
			newConfig.ChunkSize = *req.ChunkSize
		}
		if req.CompressionEnabled != nil {
			newConfig.CompressionEnabled = *req.CompressionEnabled
		}
		if req.MaxRetries != nil {
			newConfig.MaxRetries = *req.MaxRetries
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleCache handles cache configuration
func (s *ConfigAPIServer) handleCache(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"cache_enabled":   config.CacheEnabled,
			"cache_endpoints": config.CacheEndpoints,
		})
		
	case http.MethodPut:
		var req struct {
			CacheEnabled   *bool    `json:"cache_enabled,omitempty"`
			CacheEndpoints []string `json:"cache_endpoints,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		
		if req.CacheEnabled != nil {
			newConfig.CacheEnabled = *req.CacheEnabled
		}
		if req.CacheEndpoints != nil {
			newConfig.CacheEndpoints = req.CacheEndpoints
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleMetadata handles metadata configuration
func (s *ConfigAPIServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"metadata_db_type":      config.MetadataDBType,
			"metadata_db_endpoints": config.MetadataDBEndpoints,
		})
		
	case http.MethodPut:
		var req struct {
			MetadataDBType      string   `json:"metadata_db_type,omitempty"`
			MetadataDBEndpoints []string `json:"metadata_db_endpoints,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		
		if req.MetadataDBType != "" {
			newConfig.MetadataDBType = req.MetadataDBType
		}
		if req.MetadataDBEndpoints != nil {
			newConfig.MetadataDBEndpoints = req.MetadataDBEndpoints
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// handleReplicaManager handles replica manager configuration
func (s *ConfigAPIServer) handleReplicaManager(w http.ResponseWriter, r *http.Request) {
	config := s.configManager.GetConfig()
	
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"replica_manager_enabled":    config.ReplicaManagerEnabled,
			"analysis_interval":          config.AnalysisInterval.String(),
			"rebalancing_interval":       config.RebalancingInterval.String(),
			"geographic_optimization":    config.GeographicOptimization,
			"load_balancing_enabled":     config.LoadBalancingEnabled,
			"hot_data_threshold":         config.HotDataThreshold,
			"warm_data_threshold":        config.WarmDataThreshold,
			"cold_data_threshold":        config.ColdDataThreshold,
		})
		
	case http.MethodPut:
		var req struct {
			ReplicaManagerEnabled    *bool   `json:"replica_manager_enabled,omitempty"`
			AnalysisInterval         string  `json:"analysis_interval,omitempty"`
			RebalancingInterval      string  `json:"rebalancing_interval,omitempty"`
			GeographicOptimization   *bool   `json:"geographic_optimization,omitempty"`
			LoadBalancingEnabled     *bool   `json:"load_balancing_enabled,omitempty"`
			HotDataThreshold         *int64  `json:"hot_data_threshold,omitempty"`
			WarmDataThreshold        *int64  `json:"warm_data_threshold,omitempty"`
			ColdDataThreshold        *int64  `json:"cold_data_threshold,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid JSON: %v", err))
			return
		}
		
		newConfig := *config
		
		if req.ReplicaManagerEnabled != nil {
			newConfig.ReplicaManagerEnabled = *req.ReplicaManagerEnabled
		}
		if req.AnalysisInterval != "" {
			if d, err := time.ParseDuration(req.AnalysisInterval); err == nil {
				newConfig.AnalysisInterval = d
			} else {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid analysis_interval: %v", err))
				return
			}
		}
		if req.RebalancingInterval != "" {
			if d, err := time.ParseDuration(req.RebalancingInterval); err == nil {
				newConfig.RebalancingInterval = d
			} else {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid rebalancing_interval: %v", err))
				return
			}
		}
		if req.GeographicOptimization != nil {
			newConfig.GeographicOptimization = *req.GeographicOptimization
		}
		if req.LoadBalancingEnabled != nil {
			newConfig.LoadBalancingEnabled = *req.LoadBalancingEnabled
		}
		if req.HotDataThreshold != nil {
			newConfig.HotDataThreshold = *req.HotDataThreshold
		}
		if req.WarmDataThreshold != nil {
			newConfig.WarmDataThreshold = *req.WarmDataThreshold
		}
		if req.ColdDataThreshold != nil {
			newConfig.ColdDataThreshold = *req.ColdDataThreshold
		}
		
		if err := s.configManager.UpdateConfig(&newConfig); err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Update failed: %v", err))
			return
		}
		
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// corsMiddleware adds CORS headers
func (s *ConfigAPIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs HTTP requests
func (s *ConfigAPIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapper, r)
		
		duration := time.Since(start)
		s.logger.Printf("%s %s %d %v %s", r.Method, r.URL.Path, wrapper.statusCode, duration, r.RemoteAddr)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// writeJSON writes a JSON response
func (s *ConfigAPIServer) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Printf("Failed to encode JSON response: %v", err)
	}
}

// writeError writes an error response
func (s *ConfigAPIServer) writeError(w http.ResponseWriter, statusCode int, message string) {
	s.writeJSON(w, statusCode, map[string]interface{}{
		"error":     true,
		"message":   message,
		"timestamp": time.Now().UTC(),
	})
}
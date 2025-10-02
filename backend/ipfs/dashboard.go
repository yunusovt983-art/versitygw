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
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"
)

// DashboardServer provides a web interface for monitoring IPFS integration
type DashboardServer struct {
	metricsManager *IPFSMetricsManager
	server         *http.Server
	logger         *log.Logger
}

// DashboardData represents the data structure for the dashboard
type DashboardData struct {
	Timestamp    time.Time                  `json:"timestamp"`
	PinMetrics   *DashboardPinMetrics       `json:"pin_metrics"`
	ClusterMetrics *DashboardClusterMetrics `json:"cluster_metrics"`
	UsageMetrics *DashboardUsageMetrics     `json:"usage_metrics"`
	Alerts       []*Alert                   `json:"alerts"`
	SystemInfo   *DashboardSystemInfo       `json:"system_info"`
}

// DashboardPinMetrics represents pin-related metrics for the dashboard
type DashboardPinMetrics struct {
	PinLatencyP50    string  `json:"pin_latency_p50"`
	PinLatencyP95    string  `json:"pin_latency_p95"`
	PinLatencyP99    string  `json:"pin_latency_p99"`
	PinThroughput    float64 `json:"pin_throughput"`
	UnpinThroughput  float64 `json:"unpin_throughput"`
	PinErrorRate     float64 `json:"pin_error_rate"`
	UnpinErrorRate   float64 `json:"unpin_error_rate"`
	QueueDepth       int64   `json:"queue_depth"`
	TotalPins        int64   `json:"total_pins"`
	TotalUnpins      int64   `json:"total_unpins"`
}

// DashboardClusterMetrics represents cluster-related metrics for the dashboard
type DashboardClusterMetrics struct {
	HealthyNodes      int64     `json:"healthy_nodes"`
	UnhealthyNodes    int64     `json:"unhealthy_nodes"`
	TotalNodes        int64     `json:"total_nodes"`
	HealthPercentage  float64   `json:"health_percentage"`
	SplitBrainCount   int64     `json:"split_brain_count"`
	LastSplitBrain    time.Time `json:"last_split_brain"`
	NetworkLatencyP95 string    `json:"network_latency_p95"`
	NetworkErrorRate  float64   `json:"network_error_rate"`
	TotalStorage      int64     `json:"total_storage"`
	UsedStorage       int64     `json:"used_storage"`
	StorageUtilization float64  `json:"storage_utilization"`
}

// DashboardUsageMetrics represents usage-related metrics for the dashboard
type DashboardUsageMetrics struct {
	HotObjects         int64                      `json:"hot_objects"`
	WarmObjects        int64                      `json:"warm_objects"`
	ColdObjects        int64                      `json:"cold_objects"`
	TotalObjects       int64                      `json:"total_objects"`
	TopAccessedObjects []*ObjectAccessMetrics     `json:"top_accessed_objects"`
	BucketStats        []*BucketAccessMetrics     `json:"bucket_stats"`
	GeographicStats    []*GeographicAccessMetrics `json:"geographic_stats"`
	HourlyAccess       []TimePoint                `json:"hourly_access"`
	DailyAccess        []TimePoint                `json:"daily_access"`
}

// DashboardSystemInfo represents system information for the dashboard
type DashboardSystemInfo struct {
	Uptime           time.Duration `json:"uptime"`
	Version          string        `json:"version"`
	GoVersion        string        `json:"go_version"`
	MetricsEnabled   bool          `json:"metrics_enabled"`
	AlertsEnabled    bool          `json:"alerts_enabled"`
	DashboardEnabled bool          `json:"dashboard_enabled"`
}

// NewDashboardServer creates a new dashboard server
func NewDashboardServer(metricsManager *IPFSMetricsManager, port int, logger *log.Logger) *DashboardServer {
	if logger == nil {
		logger = log.Default()
	}
	
	dashboard := &DashboardServer{
		metricsManager: metricsManager,
		logger:         logger,
	}
	
	// Create HTTP server
	mux := http.NewServeMux()
	
	// Register routes
	mux.HandleFunc("/", dashboard.handleDashboard)
	mux.HandleFunc("/api/metrics", dashboard.handleAPIMetrics)
	mux.HandleFunc("/api/alerts", dashboard.handleAPIAlerts)
	mux.HandleFunc("/api/health", dashboard.handleAPIHealth)
	mux.HandleFunc("/static/", dashboard.handleStatic)
	
	dashboard.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	
	return dashboard
}

// Start starts the dashboard server
func (d *DashboardServer) Start() error {
	d.logger.Printf("Starting IPFS dashboard server on %s", d.server.Addr)
	
	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			d.logger.Printf("Dashboard server error: %v", err)
		}
	}()
	
	return nil
}

// Stop stops the dashboard server
func (d *DashboardServer) Stop() error {
	d.logger.Println("Stopping IPFS dashboard server")
	return d.server.Close()
}

// handleDashboard serves the main dashboard page
func (d *DashboardServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Get dashboard data
	data := d.getDashboardData()
	
	// Render HTML template
	tmpl := d.getDashboardTemplate()
	if err := tmpl.Execute(w, data); err != nil {
		d.logger.Printf("Error rendering dashboard template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleAPIMetrics serves metrics data as JSON
func (d *DashboardServer) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	data := d.getDashboardData()
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Printf("Error encoding metrics JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleAPIAlerts serves alerts data as JSON
func (d *DashboardServer) handleAPIAlerts(w http.ResponseWriter, r *http.Request) {
	var alerts []*Alert
	
	if d.metricsManager != nil && d.metricsManager.alertManager != nil {
		// Get limit from query parameter
		limitStr := r.URL.Query().Get("limit")
		limit := 50 // default limit
		if limitStr != "" {
			if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
				limit = parsedLimit
			}
		}
		
		// Get alert type from query parameter
		alertType := r.URL.Query().Get("type")
		switch alertType {
		case "active":
			alerts = d.metricsManager.alertManager.GetActiveAlerts()
		case "history":
			alerts = d.metricsManager.alertManager.GetAlertHistory(limit)
		default:
			// Return both active and recent history
			active := d.metricsManager.alertManager.GetActiveAlerts()
			history := d.metricsManager.alertManager.GetAlertHistory(limit - len(active))
			alerts = append(active, history...)
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(alerts); err != nil {
		d.logger.Printf("Error encoding alerts JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleAPIHealth serves health check endpoint
func (d *DashboardServer) handleAPIHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"services": map[string]string{
			"metrics_manager": "running",
			"dashboard":       "running",
		},
	}
	
	// Check if metrics manager is running
	if d.metricsManager != nil {
		d.metricsManager.mu.RLock()
		running := d.metricsManager.running
		d.metricsManager.mu.RUnlock()
		
		if running {
			health["services"].(map[string]string)["metrics_manager"] = "running"
		} else {
			health["services"].(map[string]string)["metrics_manager"] = "stopped"
			health["status"] = "degraded"
		}
	} else {
		health["services"].(map[string]string)["metrics_manager"] = "not_configured"
		health["status"] = "degraded"
	}
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		d.logger.Printf("Error encoding health JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleStatic serves static files (CSS, JS, images)
func (d *DashboardServer) handleStatic(w http.ResponseWriter, r *http.Request) {
	// For now, just return a simple CSS
	if r.URL.Path == "/static/dashboard.css" {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte(d.getDashboardCSS()))
		return
	}
	
	if r.URL.Path == "/static/dashboard.js" {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(d.getDashboardJS()))
		return
	}
	
	http.NotFound(w, r)
}

// getDashboardData collects all dashboard data
func (d *DashboardServer) getDashboardData() *DashboardData {
	data := &DashboardData{
		Timestamp: time.Now(),
		SystemInfo: &DashboardSystemInfo{
			Version:          "1.0.0", // This would come from build info
			GoVersion:        "go1.21", // This would come from runtime
			MetricsEnabled:   d.metricsManager != nil,
			AlertsEnabled:    d.metricsManager != nil && d.metricsManager.alertManager != nil,
			DashboardEnabled: true,
		},
	}
	
	if d.metricsManager != nil {
		// Get metrics from the manager
		metricsData := d.metricsManager.GetDashboardData()
		
		// Convert pin metrics
		if pinMetrics, ok := metricsData["pin_metrics"].(map[string]interface{}); ok {
			data.PinMetrics = &DashboardPinMetrics{
				PinLatencyP50:   formatDuration(pinMetrics["pin_latency_p50"]),
				PinLatencyP95:   formatDuration(pinMetrics["pin_latency_p95"]),
				PinLatencyP99:   formatDuration(pinMetrics["pin_latency_p99"]),
				PinThroughput:   getFloat64(pinMetrics["pin_throughput"]),
				UnpinThroughput: getFloat64(pinMetrics["unpin_throughput"]),
				PinErrorRate:    getFloat64(pinMetrics["pin_error_rate"]),
				UnpinErrorRate:  getFloat64(pinMetrics["unpin_error_rate"]),
				QueueDepth:      getInt64(pinMetrics["queue_depth"]),
			}
		}
		
		// Convert cluster metrics
		if clusterMetrics, ok := metricsData["cluster_metrics"].(map[string]interface{}); ok {
			healthy := getInt64(clusterMetrics["healthy_nodes"])
			total := getInt64(clusterMetrics["total_nodes"])
			var healthPercentage float64
			if total > 0 {
				healthPercentage = float64(healthy) / float64(total) * 100
			}
			
			data.ClusterMetrics = &DashboardClusterMetrics{
				HealthyNodes:       healthy,
				UnhealthyNodes:     getInt64(clusterMetrics["unhealthy_nodes"]),
				TotalNodes:         total,
				HealthPercentage:   healthPercentage,
				SplitBrainCount:    getInt64(clusterMetrics["split_brain_count"]),
				LastSplitBrain:     getTime(clusterMetrics["last_split_brain"]),
				NetworkLatencyP95:  formatDuration(clusterMetrics["network_latency_p95"]),
				NetworkErrorRate:   getFloat64(clusterMetrics["network_error_rate"]),
				TotalStorage:       getInt64(clusterMetrics["total_storage"]),
				UsedStorage:        getInt64(clusterMetrics["used_storage"]),
			}
			
			// Calculate storage utilization
			if data.ClusterMetrics.TotalStorage > 0 {
				data.ClusterMetrics.StorageUtilization = float64(data.ClusterMetrics.UsedStorage) / float64(data.ClusterMetrics.TotalStorage) * 100
			}
		}
		
		// Convert usage metrics
		if usageMetrics, ok := metricsData["usage_metrics"].(map[string]interface{}); ok {
			hot := getInt64(usageMetrics["hot_objects"])
			warm := getInt64(usageMetrics["warm_objects"])
			cold := getInt64(usageMetrics["cold_objects"])
			
			data.UsageMetrics = &DashboardUsageMetrics{
				HotObjects:   hot,
				WarmObjects:  warm,
				ColdObjects:  cold,
				TotalObjects: hot + warm + cold,
			}
			
			// Get time series data
			if hourlyAccess, ok := usageMetrics["hourly_access"].([]TimePoint); ok {
				data.UsageMetrics.HourlyAccess = hourlyAccess
			}
			if dailyAccess, ok := usageMetrics["daily_access"].([]TimePoint); ok {
				data.UsageMetrics.DailyAccess = dailyAccess
			}
		}
		
		// Get alerts
		if alerts, ok := metricsData["alerts"].([]*Alert); ok {
			data.Alerts = alerts
		}
	}
	
	return data
}

// Helper functions for type conversion

func formatDuration(v interface{}) string {
	if duration, ok := v.(time.Duration); ok {
		return duration.String()
	}
	return "N/A"
}

func getFloat64(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0.0
}

func getInt64(v interface{}) int64 {
	if i, ok := v.(int64); ok {
		return i
	}
	return 0
}

func getTime(v interface{}) time.Time {
	if t, ok := v.(time.Time); ok {
		return t
	}
	return time.Time{}
}

// getDashboardTemplate returns the HTML template for the dashboard
func (d *DashboardServer) getDashboardTemplate() *template.Template {
	tmplStr := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPFS-Cluster Integration Dashboard</title>
    <link rel="stylesheet" href="/static/dashboard.css">
    <script src="/static/dashboard.js"></script>
</head>
<body>
    <div class="container">
        <header>
            <h1>IPFS-Cluster Integration Dashboard</h1>
            <div class="timestamp">Last Updated: {{.Timestamp.Format "2006-01-02 15:04:05"}}</div>
        </header>

        <div class="metrics-grid">
            <!-- Pin Metrics -->
            <div class="metric-card">
                <h2>Pin Operations</h2>
                {{if .PinMetrics}}
                <div class="metric-row">
                    <span class="metric-label">Latency P95:</span>
                    <span class="metric-value">{{.PinMetrics.PinLatencyP95}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Pin Throughput:</span>
                    <span class="metric-value">{{printf "%.2f" .PinMetrics.PinThroughput}} ops/sec</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Error Rate:</span>
                    <span class="metric-value {{if gt .PinMetrics.PinErrorRate 0.1}}error{{end}}">{{printf "%.2f%%" (mul .PinMetrics.PinErrorRate 100)}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Queue Depth:</span>
                    <span class="metric-value {{if gt .PinMetrics.QueueDepth 1000}}warning{{end}}">{{.PinMetrics.QueueDepth}}</span>
                </div>
                {{else}}
                <div class="no-data">No pin metrics available</div>
                {{end}}
            </div>

            <!-- Cluster Health -->
            <div class="metric-card">
                <h2>Cluster Health</h2>
                {{if .ClusterMetrics}}
                <div class="metric-row">
                    <span class="metric-label">Health:</span>
                    <span class="metric-value {{if lt .ClusterMetrics.HealthPercentage 70}}error{{else if lt .ClusterMetrics.HealthPercentage 90}}warning{{end}}">{{printf "%.1f%%" .ClusterMetrics.HealthPercentage}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Nodes:</span>
                    <span class="metric-value">{{.ClusterMetrics.HealthyNodes}}/{{.ClusterMetrics.TotalNodes}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Split-Brain:</span>
                    <span class="metric-value {{if gt .ClusterMetrics.SplitBrainCount 0}}error{{end}}">{{.ClusterMetrics.SplitBrainCount}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Network Latency P95:</span>
                    <span class="metric-value">{{.ClusterMetrics.NetworkLatencyP95}}</span>
                </div>
                {{else}}
                <div class="no-data">No cluster metrics available</div>
                {{end}}
            </div>

            <!-- Usage Analytics -->
            <div class="metric-card">
                <h2>Usage Analytics</h2>
                {{if .UsageMetrics}}
                <div class="metric-row">
                    <span class="metric-label">Total Objects:</span>
                    <span class="metric-value">{{.UsageMetrics.TotalObjects}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Hot Objects:</span>
                    <span class="metric-value">{{.UsageMetrics.HotObjects}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Warm Objects:</span>
                    <span class="metric-value">{{.UsageMetrics.WarmObjects}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Cold Objects:</span>
                    <span class="metric-value">{{.UsageMetrics.ColdObjects}}</span>
                </div>
                {{else}}
                <div class="no-data">No usage metrics available</div>
                {{end}}
            </div>

            <!-- System Info -->
            <div class="metric-card">
                <h2>System Information</h2>
                {{if .SystemInfo}}
                <div class="metric-row">
                    <span class="metric-label">Version:</span>
                    <span class="metric-value">{{.SystemInfo.Version}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Go Version:</span>
                    <span class="metric-value">{{.SystemInfo.GoVersion}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Metrics:</span>
                    <span class="metric-value {{if .SystemInfo.MetricsEnabled}}success{{else}}error{{end}}">{{if .SystemInfo.MetricsEnabled}}Enabled{{else}}Disabled{{end}}</span>
                </div>
                <div class="metric-row">
                    <span class="metric-label">Alerts:</span>
                    <span class="metric-value {{if .SystemInfo.AlertsEnabled}}success{{else}}warning{{end}}">{{if .SystemInfo.AlertsEnabled}}Enabled{{else}}Disabled{{end}}</span>
                </div>
                {{else}}
                <div class="no-data">No system info available</div>
                {{end}}
            </div>
        </div>

        <!-- Alerts Section -->
        <div class="alerts-section">
            <h2>Active Alerts</h2>
            {{if .Alerts}}
            <div class="alerts-list">
                {{range .Alerts}}
                {{if not .Resolved}}
                <div class="alert alert-{{.Rule.Severity}}">
                    <div class="alert-header">
                        <span class="alert-name">{{.Rule.Name}}</span>
                        <span class="alert-time">{{.Timestamp.Format "15:04:05"}}</span>
                    </div>
                    <div class="alert-message">{{.Message}}</div>
                </div>
                {{end}}
                {{end}}
            </div>
            {{else}}
            <div class="no-alerts">No active alerts</div>
            {{end}}
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setInterval(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
`
	
	// Add template functions
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}
	
	return template.Must(template.New("dashboard").Funcs(funcMap).Parse(tmplStr))
}

// getDashboardCSS returns the CSS for the dashboard
func (d *DashboardServer) getDashboardCSS() string {
	return `
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    margin: 0;
    padding: 20px;
    background-color: #f5f5f5;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
}

header {
    text-align: center;
    margin-bottom: 30px;
    padding: 20px;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

header h1 {
    margin: 0 0 10px 0;
    color: #2c3e50;
}

.timestamp {
    color: #7f8c8d;
    font-size: 14px;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metric-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.metric-card h2 {
    margin: 0 0 15px 0;
    color: #2c3e50;
    font-size: 18px;
    border-bottom: 2px solid #ecf0f1;
    padding-bottom: 10px;
}

.metric-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 0;
    border-bottom: 1px solid #ecf0f1;
}

.metric-row:last-child {
    border-bottom: none;
}

.metric-label {
    font-weight: 500;
    color: #34495e;
}

.metric-value {
    font-weight: 600;
    color: #2c3e50;
}

.metric-value.success {
    color: #27ae60;
}

.metric-value.warning {
    color: #f39c12;
}

.metric-value.error {
    color: #e74c3c;
}

.no-data {
    text-align: center;
    color: #7f8c8d;
    font-style: italic;
    padding: 20px;
}

.alerts-section {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.alerts-section h2 {
    margin: 0 0 15px 0;
    color: #2c3e50;
    font-size: 18px;
    border-bottom: 2px solid #ecf0f1;
    padding-bottom: 10px;
}

.alerts-list {
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.alert {
    padding: 15px;
    border-radius: 6px;
    border-left: 4px solid;
}

.alert-0 { /* Info */
    background-color: #d4edda;
    border-left-color: #28a745;
}

.alert-1 { /* Warning */
    background-color: #fff3cd;
    border-left-color: #ffc107;
}

.alert-2 { /* Critical */
    background-color: #f8d7da;
    border-left-color: #dc3545;
}

.alert-3 { /* Emergency */
    background-color: #f8d7da;
    border-left-color: #721c24;
}

.alert-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 5px;
}

.alert-name {
    font-weight: 600;
    text-transform: uppercase;
    font-size: 12px;
}

.alert-time {
    font-size: 12px;
    color: #6c757d;
}

.alert-message {
    font-size: 14px;
    line-height: 1.4;
}

.no-alerts {
    text-align: center;
    color: #27ae60;
    font-weight: 500;
    padding: 20px;
}

@media (max-width: 768px) {
    .metrics-grid {
        grid-template-columns: 1fr;
    }
    
    .metric-row {
        flex-direction: column;
        align-items: flex-start;
        gap: 5px;
    }
}
`
}

// getDashboardJS returns the JavaScript for the dashboard
func (d *DashboardServer) getDashboardJS() string {
	return `
// Dashboard JavaScript functionality

class IPFSDashboard {
    constructor() {
        this.refreshInterval = 30000; // 30 seconds
        this.init();
    }
    
    init() {
        this.setupAutoRefresh();
        this.setupEventListeners();
        console.log('IPFS Dashboard initialized');
    }
    
    setupAutoRefresh() {
        setInterval(() => {
            this.refreshData();
        }, this.refreshInterval);
    }
    
    setupEventListeners() {
        // Add click handlers for interactive elements
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('metric-card')) {
                this.showDetailedMetrics(e.target);
            }
        });
    }
    
    async refreshData() {
        try {
            const response = await fetch('/api/metrics');
            const data = await response.json();
            this.updateDashboard(data);
        } catch (error) {
            console.error('Failed to refresh dashboard data:', error);
        }
    }
    
    updateDashboard(data) {
        // Update timestamp
        const timestampEl = document.querySelector('.timestamp');
        if (timestampEl) {
            timestampEl.textContent = 'Last Updated: ' + new Date(data.timestamp).toLocaleString();
        }
        
        // Update metrics would go here
        // For now, just log that we received data
        console.log('Dashboard data updated:', data);
    }
    
    showDetailedMetrics(cardElement) {
        // This would show a modal or expanded view with detailed metrics
        console.log('Show detailed metrics for:', cardElement);
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new IPFSDashboard();
});

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
    if (ms < 1000) return ms + 'ms';
    if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
    if (ms < 3600000) return (ms / 60000).toFixed(1) + 'm';
    return (ms / 3600000).toFixed(1) + 'h';
}
`
}
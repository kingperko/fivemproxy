package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ------------------------
// Configuration
// ------------------------

// If you want more detailed logging (for debugging), set this to true.
const debugMode = false

// For Discord notifications (set to false if you do not want them at all).
const disableDiscord = false

// Adjust these to tune rate limiting:
const (
	tcpBucketCapacity   = 20.0 // Maximum tokens per IP for TCP connections
	tcpBucketRefillRate = 2.0  // Tokens per second refill for TCP

	udpBucketCapacity   = 50.0 // Maximum tokens per IP for UDP packets
	udpBucketRefillRate = 10.0 // Tokens per second refill for UDP
)

// DDoS drop threshold per interval (10s) for sending an alert.
const dropThreshold = 200

// ------------------------
// Discord Notification Support
// ------------------------

type discordEmbed struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
}

type discordWebhookBody struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

func sendDiscordEmbed(webhookURL, title, description string, color int) {
	if disableDiscord || webhookURL == "" {
		return
	}
	embed := discordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
	}
	payload := discordWebhookBody{
		Username: "Enhanced Firewall",
		Embeds:   []discordEmbed{embed},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[DISCORD] JSON marshal error: %v", err)
		return
	}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[DISCORD] Request creation error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DISCORD] Request error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("[DISCORD] Unexpected status code: %d", resp.StatusCode)
	}
}

func sendDDoSAttackStarted(webhookURL, serverName, serverIP, targetPort string) {
	title := "Enhanced Firewall Alert"
	description := "Mitigation started: High drop rates detected. DDoS attack in progress."
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

func sendDDoSAttackEnded(webhookURL, serverName, serverIP, targetPort string) {
	title := "Enhanced Firewall Alert"
	description := "Mitigation ended: Traffic levels have normalized."
	sendDiscordEmbed(webhookURL, title, description, 0x00ff00)
}

// ------------------------
// Logging Helpers
// ------------------------

func debugLog(format string, v ...interface{}) {
	if debugMode {
		log.Printf(format, v...)
	}
}

// ------------------------
// Global Firewall Variables & Helpers
// ------------------------

var (
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	tcpConnCount int64 // track total TCP connections (for optional stats)
)

func updateWhitelist(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// ------------------------
// Token Bucket Implementation for Rate Limiting
// ------------------------

type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func (tb *TokenBucket) Allow(cost float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	// Refill tokens based on elapsed time:
	tb.tokens = math.Min(tb.capacity, tb.tokens+tb.refillRate*elapsed)
	tb.lastRefill = now

	if tb.tokens >= cost {
		tb.tokens -= cost
		return true
	}
	return false
}

var (
	tcpBuckets   = make(map[string]*TokenBucket)
	tcpBucketsMu sync.RWMutex

	udpBuckets   = make(map[string]*TokenBucket)
	udpBucketsMu sync.RWMutex
)

func getTCPBucket(ip string) *TokenBucket {
	tcpBucketsMu.RLock()
	bucket, exists := tcpBuckets[ip]
	tcpBucketsMu.RUnlock()
	if !exists {
		tcpBucketsMu.Lock()
		bucket, exists = tcpBuckets[ip]
		if !exists {
			bucket = &TokenBucket{
				capacity:   tcpBucketCapacity,
				tokens:     tcpBucketCapacity,
				refillRate: tcpBucketRefillRate,
				lastRefill: time.Now(),
			}
			tcpBuckets[ip] = bucket
		}
		tcpBucketsMu.Unlock()
	}
	return bucket
}

func getUDPBucket(ip string) *TokenBucket {
	udpBucketsMu.RLock()
	bucket, exists := udpBuckets[ip]
	udpBucketsMu.RUnlock()
	if !exists {
		udpBucketsMu.Lock()
		bucket, exists = udpBuckets[ip]
		if !exists {
			bucket = &TokenBucket{
				capacity:   udpBucketCapacity,
				tokens:     udpBucketCapacity,
				refillRate: udpBucketRefillRate,
				lastRefill: time.Now(),
			}
			udpBuckets[ip] = bucket
		}
		udpBucketsMu.Unlock()
	}
	return bucket
}

// Global counters for dropped connections/packets due to rate limiting.
var (
	tcpDropCount uint64
	udpDropCount uint64
)

// ------------------------
// Handshake Detection Helpers (TCP only)
// ------------------------

func isTCPHandshake(data []byte) bool {
	// Basic TLS handshake check
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03)
}

func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client") ||
		strings.Contains(lower, "citizenfx")
}

// ------------------------
// TCP Proxy Logic
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Immediately drop if banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		return
	}
	bannedIPsMu.RUnlock()

	// Rate limiting for non-whitelisted IPs:
	if !isWhitelisted(clientIP) {
		bucket := getTCPBucket(clientIP)
		if !bucket.Allow(1) {
			atomic.AddUint64(&tcpDropCount, 1)
			debugLog("[TCP] [%s] Dropped: Rate limit exceeded", clientIP)
			return
		}
	}

	// Read initial handshake data (3s timeout).
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		debugLog("[TCP] [%s] Handshake read error: %v", clientIP, err)
		return
	}

	// Validate handshake (TLS or FiveM).
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		debugLog("[TCP] [%s] Invalid handshake - banning IP", clientIP)
		banIP(clientIP)
		return
	}

	// Valid handshake: whitelist the IP so it won't get bucket-limited next time.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	debugLog("[TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()

	// Forward handshake data:
	_, _ = backendConn.Write(buf[:n])
	proxyTCPWithConn(conn, backendConn, clientIP)
}

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Backend dial error: %v", err)
		return
	}
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()
	proxyTCPWithConn(client, backendConn, client.RemoteAddr().String())
}

func proxyTCPWithConn(client, backend net.Conn, clientIP string) {
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(backend, client)
		if err != nil && debugMode {
			log.Printf("[TCP] [%s] Error copying from client to backend: %v", clientIP, err)
		}
		backend.Close()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		if err != nil && debugMode {
			log.Printf("[TCP] [%s] Error copying from backend to client: %v", clientIP, err)
		}
		client.Close()
	}()

	wg.Wait()
	debugLog("[TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic (No strict handshake check)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastActive  time.Time
	closeOnce   sync.Once
}

var (
	sessionMap = make(map[string]*sessionData)
	sessionMu  sync.Mutex
)

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	listenAddr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[UDP] Error resolving listen address: %v", err)
	}
	listenConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatalf("[UDP] Error starting UDP listener on port %s: %v", listenPort, err)
	}
	log.Printf("[UDP] Listening on port %s", listenPort)

	backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf("[UDP] Error resolving backend address: %v", err)
	}

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		clientIP := clientAddr.IP.String()

		// Immediately drop if banned.
		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			continue
		}
		bannedIPsMu.RUnlock()

		// Apply token bucket if not whitelisted.
		if !isWhitelisted(clientIP) {
			bucket := getUDPBucket(clientIP)
			if !bucket.Allow(1) {
				atomic.AddUint64(&udpDropCount, 1)
				debugLog("[UDP] [%s] Dropped packet: Rate limit exceeded", clientAddr.String())
				continue
			}
		}

		// Create or update session
		clientKey := clientAddr.String()
		sessionMu.Lock()
		sd, exists := sessionMap[clientKey]
		if !exists {
			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				sessionMu.Unlock()
				debugLog("[UDP] Error dialing backend for client %s: %v", clientKey, err)
				continue
			}
			sd = &sessionData{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMap[clientKey] = sd

			// Spin up a goroutine to handle traffic from backend -> client
			go handleUDPSession(listenConn, sd)
		} else {
			sd.lastActive = time.Now()
		}
		sessionMu.Unlock()

		_, err = sd.backendConn.Write(buf[:n])
		if err != nil && debugMode {
			log.Printf("[UDP] Write to backend error for client %s: %v", clientKey, err)
		}
	}
}

func handleUDPSession(listenConn *net.UDPConn, sd *sessionData) {
	buf := make([]byte, 2048)
	for {
		sd.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sd.backendConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			debugLog("[UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil && debugMode {
			log.Printf("[UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
}

// ------------------------
// DDoS Drop-Count Monitor
// ------------------------

func monitorDrops(discordWebhook string) {
	const interval = 10 * time.Second
	var attackActive bool
	var consecutiveLow int

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		tcpDrops := atomic.LoadUint64(&tcpDropCount)
		udpDrops := atomic.LoadUint64(&udpDropCount)
		totalDrops := tcpDrops + udpDrops

		// Only log or alert if we cross threshold or if we end an active attack:
		if totalDrops > dropThreshold {
			if !attackActive {
				sendDDoSAttackStarted(discordWebhook, "Firewall", "", "")
				log.Printf("[DDoS Alert] Attack detected: drops=%d (> %d)", totalDrops, dropThreshold)
				attackActive = true
			}
			consecutiveLow = 0
		} else {
			if attackActive {
				consecutiveLow++
				// Once we've been below threshold for 2 consecutive intervals:
				if consecutiveLow >= 2 {
					sendDDoSAttackEnded(discordWebhook, "Firewall", "", "")
					log.Printf("[DDoS Alert] Attack subsided: drops back below threshold")
					attackActive = false
					consecutiveLow = 0
				}
			}
		}

		// Reset counters
		atomic.StoreUint64(&tcpDropCount, 0)
		atomic.StoreUint64(&udpDropCount, 0)
	}
}

// ------------------------
// Main Function
// ------------------------

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL for alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	log.Printf("[INFO] Starting enhanced firewall proxy: forwarding to %s:%s on port %s",
		*targetIP, *targetPort, *listenPort)

	// Start TCP proxy listener
	go func() {
		ln, err := net.Listen("tcp", ":"+*listenPort)
		if err != nil {
			log.Fatalf("[TCP] Listen error on port %s: %v", *listenPort, err)
		}
		defer ln.Close()
		log.Printf("[TCP] Listening on port %s", *listenPort)

		for {
			conn, err := ln.Accept()
			if err != nil {
				if debugMode {
					log.Printf("[TCP] Accept error: %v", err)
				}
				continue
			}
			go handleTCPConnection(conn, *targetIP, *targetPort, *discordWebhook)
		}
	}()

	// Start UDP proxy listener
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start global DDoS monitor
	go monitorDrops(*discordWebhook)

	// Block forever
	select {}
}

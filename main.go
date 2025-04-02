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
// Discord Notification Support
// ------------------------

const disableDiscord = false // Set to false to enable Discord notifications.

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
// Global Firewall Variables & Helpers
// ------------------------

var (
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	tcpConnCount int64
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

const (
	tcpBucketCapacity   = 20.0 // max tokens for TCP
	tcpBucketRefillRate = 2.0  // tokens per second for TCP

	udpBucketCapacity   = 50.0 // max tokens for UDP
	udpBucketRefillRate = 10.0 // tokens per second for UDP
)

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
// You can keep these for TCP handshake checks if you like. 
// We won't enforce them on UDP in this updated version.

func isTCPHandshake(data []byte) bool {
	// Check for basic TLS handshake bytes
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
// TCP Proxy Logic with Token Bucket Rate Limiting
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Immediately drop if the IP is banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		return
	}
	bannedIPsMu.RUnlock()

	// For non-whitelisted clients, use token bucket rate limiting.
	if !isWhitelisted(clientIP) {
		bucket := getTCPBucket(clientIP)
		if !bucket.Allow(1) {
			atomic.AddUint64(&tcpDropCount, 1)
			log.Printf("[TCP] [%s] Dropped: Rate limit exceeded", clientIP)
			return
		}
	}

	// Read initial handshake data (3s timeout).
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf("[TCP] [%s] Handshake read error: %v", clientIP, err)
		return
	}

	// Validate handshake (TLS or FiveM).
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		log.Printf("[TCP] [%s] Invalid handshake - banning IP", clientIP)
		banIP(clientIP)
		return
	}

	// Valid handshake: whitelist the IP.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf("[TCP] [%s] Authenticated and whitelisted", clientIP)

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

	// Forward the handshake data to the backend.
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
		if err != nil {
			log.Printf("[TCP] [%s] Error copying from client to backend: %v", clientIP, err)
		}
		backend.Close()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		if err != nil {
			log.Printf("[TCP] [%s] Error copying from backend to client: %v", clientIP, err)
		}
		client.Close()
	}()

	wg.Wait()
	log.Printf("[TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic WITHOUT strict handshake check
// ------------------------
// Instead of requiring a FiveM handshake, we rely on:
//   1) The token bucket for rate limiting
//   2) If an IP is already whitelisted via TCP, skip bucket checks
//   3) If an IP isn't whitelisted, we still allow the packet (so normal servers can talk back)
//      but apply the token bucket cost. If the IP floods, it gets dropped by the bucket.

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

		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			// Immediately drop if banned
			continue
		}
		bannedIPsMu.RUnlock()

		// Token bucket for non-whitelisted IP
		if !isWhitelisted(clientIP) {
			bucket := getUDPBucket(clientIP)
			if !bucket.Allow(1) {
				atomic.AddUint64(&udpDropCount, 1)
				log.Printf("[UDP] [%s] Dropped packet: Rate limit exceeded", clientAddr.String())
				continue
			}
		}

		// If desired, you could keep some minimal handshake check here.
		// For now, we let all UDP traffic pass as long as the bucket allows it.

		// Create or update session
		clientKey := clientAddr.String()
		sessionMu.Lock()
		sd, exists := sessionMap[clientKey]
		if !exists {
			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				sessionMu.Unlock()
				log.Printf("[UDP] Error dialing backend for client %s: %v", clientKey, err)
				continue
			}
			sd = &sessionData{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMap[clientKey] = sd

			// Spin up a goroutine to handle traffic from the backend -> client
			go handleUDPSession(listenConn, sd)
		} else {
			sd.lastActive = time.Now()
		}
		sessionMu.Unlock()

		_, err = sd.backendConn.Write(buf[:n])
		if err != nil {
			log.Printf("[UDP] Write to backend error for client %s: %v", clientKey, err)
			continue
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
			log.Printf("[UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil {
			log.Printf("[UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
}

// ------------------------
// Drop-Count-Based DDoS Monitor
// ------------------------

func monitorDrops(discordWebhook string) {
	const interval = 10 * time.Second
	const dropThreshold = 200
	var attackActive bool
	var consecutiveLow int

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		tcpDrops := atomic.LoadUint64(&tcpDropCount)
		udpDrops := atomic.LoadUint64(&udpDropCount)
		totalDrops := tcpDrops + udpDrops

		log.Printf("[DDoS Monitor] Total drops in last %v: %d", interval, totalDrops)

		if totalDrops > dropThreshold {
			if !attackActive {
				sendDDoSAttackStarted(discordWebhook, "Firewall", "", "")
				log.Printf("[DDoS Alert] Attack detected: Total drops (%d) exceeded threshold (%d)", totalDrops, dropThreshold)
				attackActive = true
			}
			consecutiveLow = 0
		} else {
			if attackActive {
				consecutiveLow++
				if consecutiveLow >= 2 {
					sendDDoSAttackEnded(discordWebhook, "Firewall", "", "")
					log.Printf("[DDoS Alert] Attack subsided: Drops below threshold for %d intervals", consecutiveLow)
					attackActive = false
					consecutiveLow = 0
				}
			}
		}
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
				log.Printf("[TCP] Accept error: %v", err)
				continue
			}
			go handleTCPConnection(conn, *targetIP, *targetPort, *discordWebhook)
		}
	}()

	// Start UDP proxy listener
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start global DDoS monitor based on drop counts
	go monitorDrops(*discordWebhook)

	// Block forever
	select {}
}

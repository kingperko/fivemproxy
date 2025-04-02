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
	"runtime"
)

// ------------------------
// Configuration
// ------------------------

// Set this to true if you want more detailed logs (debug).
const debugMode = false

// If you do not want Discord alerts at all, set this to true.
const disableDiscord = false

// Basic concurrency limit for new (non‐whitelisted) TCP connections from a single IP.
const maxConcurrentTCPPerIP = 3

// UDP token bucket parameters (for non‐whitelisted IPs).
// Setting these high ensures we only drop massive floods.
const (
	udpBucketCapacity   = 500.0
	udpBucketRefillRate = 100.0 // tokens/second
)

// If you still want a small TCP token bucket for brand‐new IPs, you can define it here.
const (
	tcpBucketCapacity   = 50.0
	tcpBucketRefillRate = 10.0
)

// DDoS drop threshold for alerting in each 10‐second interval.
const dropThreshold = 200

// ------------------------
// Discord Notification
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
		Username: "Firewall Proxy",
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

func sendDDoSAttackStarted(webhookURL string) {
	title := "Firewall Alert"
	description := "Mitigation started: High drop rates detected."
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

func sendDDoSAttackEnded(webhookURL string) {
	title := "Firewall Alert"
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
// Whitelist / Ban Lists
// ------------------------

var (
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex
)

func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

func whitelistIP(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

func isBanned(ip string) bool {
	bannedIPsMu.RLock()
	defer bannedIPsMu.RUnlock()
	return bannedIPs[ip]
}

func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// ------------------------
// Token Bucket
// ------------------------

type tokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64
	lastRefill time.Time
}

func (tb *tokenBucket) allow(cost float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens = math.Min(tb.capacity, tb.tokens+tb.refillRate*elapsed)
	tb.lastRefill = now

	if tb.tokens >= cost {
		tb.tokens -= cost
		return true
	}
	return false
}

var (
	udpBuckets   = make(map[string]*tokenBucket)
	udpBucketsMu sync.RWMutex

	tcpBuckets   = make(map[string]*tokenBucket)
	tcpBucketsMu sync.RWMutex
)

func getUDPTB(ip string) *tokenBucket {
	udpBucketsMu.RLock()
	tb, ok := udpBuckets[ip]
	udpBucketsMu.RUnlock()
	if !ok {
		udpBucketsMu.Lock()
		tb, ok = udpBuckets[ip]
		if !ok {
			tb = &tokenBucket{
				capacity:   udpBucketCapacity,
				tokens:     udpBucketCapacity,
				refillRate: udpBucketRefillRate,
				lastRefill: time.Now(),
			}
			udpBuckets[ip] = tb
		}
		udpBucketsMu.Unlock()
	}
	return tb
}

func getTCPTB(ip string) *tokenBucket {
	tcpBucketsMu.RLock()
	tb, ok := tcpBuckets[ip]
	tcpBucketsMu.RUnlock()
	if !ok {
		tcpBucketsMu.Lock()
		tb, ok = tcpBuckets[ip]
		if !ok {
			tb = &tokenBucket{
				capacity:   tcpBucketCapacity,
				tokens:     tcpBucketCapacity,
				refillRate: tcpBucketRefillRate,
				lastRefill: time.Now(),
			}
			tcpBuckets[ip] = tb
		}
		tcpBucketsMu.Unlock()
	}
	return tb
}

// ------------------------
// Concurrency Limits (TCP)
// ------------------------

var (
	tcpConnCountByIP   = make(map[string]int)
	tcpConnCountByIPMu sync.Mutex
)

// Increase concurrency count for IP. Returns false if above max concurrency.
func incTCPConn(ip string) bool {
	tcpConnCountByIPMu.Lock()
	defer tcpConnCountByIPMu.Unlock()
	count := tcpConnCountByIP[ip]
	if count >= maxConcurrentTCPPerIP {
		return false
	}
	tcpConnCountByIP[ip] = count + 1
	return true
}

func decTCPConn(ip string) {
	tcpConnCountByIPMu.Lock()
	defer tcpConnCountByIPMu.Unlock()
	count := tcpConnCountByIP[ip]
	if count > 0 {
		tcpConnCountByIP[ip] = count - 1
	}
}

// ------------------------
// Drop Counters for DDoS Monitoring
// ------------------------
var (
	tcpDropCount uint64
	udpDropCount uint64
)

// ------------------------
// TCP Proxy Logic
// ------------------------

func handleTCPConnection(client net.Conn, targetIP, targetPort, discordWebhook string) {
	defer client.Close()
	clientAddr := client.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()

	// Banned IP?
	if isBanned(clientIP) {
		return
	}

	// If not whitelisted, check concurrency limit.
	if !isWhitelisted(clientIP) {
		if !incTCPConn(clientIP) {
			atomic.AddUint64(&tcpDropCount, 1)
			debugLog("[TCP] %s concurrency limit reached, dropping connection", clientIP)
			return
		}
		defer decTCPConn(clientIP)

		// Also optional token bucket:
		tb := getTCPTB(clientIP)
		if !tb.allow(1) {
			atomic.AddUint64(&tcpDropCount, 1)
			debugLog("[TCP] %s token bucket exceeded, dropping connection", clientIP)
			return
		}
	}

	// Minimal handshake read (3s timeout).
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		debugLog("[TCP] %s handshake read error: %v", clientIP, err)
		return
	}

	// Basic check: if it looks like TLS or FiveM HTTP, whitelist.
	if !looksLikeTLS(buf[:n]) && !looksLikeFiveM(buf[:n]) {
		debugLog("[TCP] %s invalid handshake -> banning IP", clientIP)
		banIP(clientIP)
		return
	}
	// Whitelist IP so subsequent connections skip concurrency checks.
	whitelistIP(clientIP)
	debugLog("[TCP] %s whitelisted (valid handshake)", clientIP)

	// Connect to backend
	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] %s backend dial error: %v", clientIP, err)
		return
	}
	defer backend.Close()

	// For performance, set keepalive
	if bc, ok := backend.(*net.TCPConn); ok {
		bc.SetKeepAlive(true)
		bc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Write the handshake data to backend
	_, _ = backend.Write(buf[:n])

	// Proxy data in both directions
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Larger buffer for less CPU overhead
		_, _ = io.CopyBuffer(backend, client, make([]byte, 32*1024))
		backend.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.CopyBuffer(client, backend, make([]byte, 32*1024))
		client.Close()
	}()

	wg.Wait()
	debugLog("[TCP] %s connection closed", clientIP)
}

func looksLikeTLS(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03
}

func looksLikeFiveM(data []byte) bool {
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "citizenfx") ||
		strings.Contains(lower, "post /client")
}

// ------------------------
// UDP Proxy Logic
// ------------------------

type udpSession struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastActive  time.Time
}

var (
	udpSessionMap = make(map[string]*udpSession)
	udpSessionMu  sync.Mutex
)

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	la, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[UDP] resolve listen addr: %v", err)
	}
	listener, err := net.ListenUDP("udp", la)
	if err != nil {
		log.Fatalf("[UDP] listen error on port %s: %v", listenPort, err)
	}
	log.Printf("[UDP] Listening on port %s", listenPort)

	ba, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf("[UDP] resolve backend addr: %v", err)
	}

	buf := make([]byte, 2048)
	for {
		n, caddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		clientIP := caddr.IP.String()

		// Banned?
		if isBanned(clientIP) {
			continue
		}

		// If not whitelisted, apply UDP token bucket.
		if !isWhitelisted(clientIP) {
			tb := getUDPTB(clientIP)
			if !tb.allow(1) {
				atomic.AddUint64(&udpDropCount, 1)
				debugLog("[UDP] drop from %s (bucket exceeded)", clientIP)
				continue
			}
		}

		// Forward to backend
		key := caddr.String()
		udpSessionMu.Lock()
		sess, ok := udpSessionMap[key]
		if !ok {
			bc, err := net.DialUDP("udp", nil, ba)
			if err != nil {
				udpSessionMu.Unlock()
				continue
			}
			sess = &udpSession{
				clientAddr:  caddr,
				backendConn: bc,
				lastActive:  time.Now(),
			}
			udpSessionMap[key] = sess

			// Start read-back loop
			go handleUDPFromBackend(listener, sess)
		} else {
			sess.lastActive = time.Now()
		}
		udpSessionMu.Unlock()

		_, _ = sess.backendConn.Write(buf[:n])
	}
}

func handleUDPFromBackend(listener *net.UDPConn, sess *udpSession) {
	buf := make([]byte, 2048)
	for {
		sess.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sess.backendConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			debugLog("[UDP] backend read error for %s: %v", sess.clientAddr, err)
			break
		}
		sess.lastActive = time.Now()
		_, _ = listener.WriteToUDP(buf[:n], sess.clientAddr)
	}
}

// ------------------------
// DDoS Drop Monitor
// ------------------------

func monitorDrops(discordWebhook string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var attackActive bool
	var consecutiveBelow int

	for range ticker.C {
		td := atomic.LoadUint64(&tcpDropCount)
		ud := atomic.LoadUint64(&udpDropCount)
		total := td + ud

		// Only alert if above threshold or if ending an active attack
		if total > dropThreshold {
			if !attackActive {
				sendDDoSAttackStarted(discordWebhook)
				log.Printf("[DDoS Alert] Attack detected (drops = %d)", total)
				attackActive = true
			}
			consecutiveBelow = 0
		} else {
			if attackActive {
				consecutiveBelow++
				if consecutiveBelow >= 2 {
					sendDDoSAttackEnded(discordWebhook)
					log.Printf("[DDoS Alert] Attack subsided")
					attackActive = false
					consecutiveBelow = 0
				}
			}
		}

		// Reset counters
		atomic.StoreUint64(&tcpDropCount, 0)
		atomic.StoreUint64(&udpDropCount, 0)

		// Optional: log current goroutine count to see CPU usage over time
		if debugMode {
			log.Printf("[DEBUG] Goroutines: %d", runtime.NumGoroutine())
		}
	}
}

// ------------------------
// Main
// ------------------------

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Proxy listen port (TCP & UDP)")
	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=IP -targetPort=PORT -listenPort=PORT [-discordWebhook=URL]\n", os.Args[0])
		os.Exit(1)
	}

	log.Printf("[INFO] Starting firewall proxy -> %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	// Start TCP
	go func() {
		ln, err := net.Listen("tcp", ":"+*listenPort)
		if err != nil {
			log.Fatalf("[TCP] Listen error on %s: %v", *listenPort, err)
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

	// Start UDP
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start drop monitor
	go monitorDrops(*discordWebhook)

	// Block forever
	select {}
}

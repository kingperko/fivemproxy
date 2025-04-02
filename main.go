package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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

// Set to false to ENABLE Discord notifications.
const disableDiscord = false

// Set to true to DISABLE UDP handshake checks entirely.
const disableUDPHandshakeCheck = false

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
		Username: "Proxy Monitor",
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
	title := "Perko's Proxy Alert"
	description := "Mitigation started: An attack on your server has been detected and is being mitigated."
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

func sendDDoSAttackEnded(webhookURL, serverName, serverIP, targetPort string) {
	title := "Perko's Proxy Alert"
	description := "Mitigation ended: The attack on your server has subsided."
	sendDiscordEmbed(webhookURL, title, description, 0x00ff00)
}

// ------------------------
// Global Variables & Helpers
// ------------------------

var (
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	tcpConnCount int64
)

// Tracks if we are under DDoS
var (
	ddosAttackActive bool
	ddosMutex        sync.RWMutex
)

// isDDoSActive returns true if we are currently under attack.
func isDDoSActive() bool {
	ddosMutex.RLock()
	defer ddosMutex.RUnlock()
	return ddosAttackActive
}

// setDDoSActive sets the ddosAttackActive state.
func setDDoSActive(active bool) {
	ddosMutex.Lock()
	defer ddosMutex.Unlock()
	ddosAttackActive = active
}

// ------------------------
// Whitelist & Banning
// ------------------------

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
	log.Printf("[BAN] IP %s has been banned.", ip)
}

// ------------------------
// Handshake Failure Tracking
// ------------------------

var (
	tcpHandshakeFailures   = make(map[string]int)
	tcpHandshakeFailuresMu sync.Mutex
	handshakeFailureLimit  = 2

	udpHandshakeFailures   = make(map[string]int)
	udpHandshakeFailuresMu sync.Mutex
	udpHandshakeFailureLimit = 2
)

// ------------------------
// Rate Limiting for DDoS Prevention
// ------------------------

var (
	connectionRates   = make(map[string]int)
	connectionRatesMu sync.Mutex
	tcpThreshold      = 10 // max allowed connections per 10 seconds
)

var (
	udpPacketCounts   = make(map[string]int)
	udpPacketCountsMu sync.Mutex
	udpThreshold      = 500 // allowed UDP packets per 10 seconds for non-whitelisted
)

func resetTCPCounts() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		connectionRatesMu.Lock()
		connectionRates = make(map[string]int)
		connectionRatesMu.Unlock()
	}
}

func resetUDPPacketCounts() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		udpPacketCountsMu.Lock()
		udpPacketCounts = make(map[string]int)
		udpPacketCountsMu.Unlock()
	}
}

// ------------------------
// DDoS Global Counters
// ------------------------

var (
	ddosPacketCount uint64
	ddosByteCount   uint64
)

// ------------------------
// Additional Anti-Bot Flood: Max New IPs per Minute
// ------------------------
//
// This ensures that even if an attacker replicates the handshake, 
// they can only get a certain number of new IPs whitelisted per minute.

const maxNewIPsPerMinute = 10
var (
	whitelistTimes   []time.Time
	whitelistTimesMu sync.Mutex
)

func canWhitelistNewIP() bool {
	whitelistTimesMu.Lock()
	defer whitelistTimesMu.Unlock()

	now := time.Now()
	// Remove timestamps older than 60s
	cutoff := now.Add(-60 * time.Second)
	newSlice := whitelistTimes[:0]
	for _, t := range whitelistTimes {
		if t.After(cutoff) {
			newSlice = append(newSlice, t)
		}
	}
	whitelistTimes = newSlice

	// If we already have >= maxNewIPs in the last 60s, block
	if len(whitelistTimes) >= maxNewIPsPerMinute {
		return false
	}

	// Otherwise, we can whitelist
	whitelistTimes = append(whitelistTimes, now)
	return true
}

// ------------------------
// Logging Helpers
// ------------------------

func logTCPError(prefix string, err error) {
	if err == nil {
		return
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, "use of closed network connection") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "splice: connection reset by peer") {
		return
	}
	log.Printf("[TCP] %s: %v", prefix, err)
}

// ------------------------
// Handshake Detection
// ------------------------
//
// We now REQUIRE a known FiveM route plus a known FiveM user-agent.

func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))

	// Must contain a known route
	fivemRoute := strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client")

	// Must have a known user-agent line
	fivemUserAgent := strings.Contains(lower, "user-agent: citizenfx") ||
		strings.Contains(lower, "user-agent: fxserver") ||
		strings.Contains(lower, "citizenfx")

	return fivemRoute && fivemUserAgent
}

func isTCPHandshake(data []byte) bool {
	// Basic TLS check
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
	return false
}

// ------------------------
// TCP Proxy Logic
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Immediately drop if the IP is banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf("[TCP] [%s] Connection from banned IP dropped.", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	// Rate limit: count new connections.
	connectionRatesMu.Lock()
	connectionRates[clientIP]++
	if connectionRates[clientIP] > tcpThreshold {
		bannedIPsMu.Lock()
		bannedIPs[clientIP] = true
		bannedIPsMu.Unlock()
		connectionRatesMu.Unlock()
		log.Printf("[TCP] [%s] Banned: Excessive connection attempts", clientIP)
		return
	}
	connectionRatesMu.Unlock()

	// If already whitelisted, just proxy.
	if isWhitelisted(clientIP) {
		log.Printf("[TCP] [%s] Whitelisted => connection allowed.", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// If we are under attack, block new IPs from being whitelisted.
	if isDDoSActive() {
		log.Printf("[TCP] [%s] Blocked: DDoS active, new IP not whitelisted.", clientIP)
		return
	}

	// If we've hit our limit of new IPs per minute, block this IP.
	if !canWhitelistNewIP() {
		log.Printf("[TCP] [%s] Blocked: Too many new IPs whitelisted recently.", clientIP)
		return
	}

	// Minimal handshake read to verify it's a legitimate FiveM client.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		tcpHandshakeFailuresMu.Lock()
		tcpHandshakeFailures[clientIP]++
		failCount := tcpHandshakeFailures[clientIP]
		tcpHandshakeFailuresMu.Unlock()
		log.Printf("[TCP] [%s] Handshake read error (%d/%d): %v", clientIP, failCount, handshakeFailureLimit, err)
		if failCount >= handshakeFailureLimit {
			banIP(clientIP)
		}
		return
	}

	// Must match a valid FiveM handshake or a TLS handshake
	if !isFiveMHandshake(buf[:n]) && !isTCPHandshake(buf[:n]) {
		tcpHandshakeFailuresMu.Lock()
		tcpHandshakeFailures[clientIP]++
		failCount := tcpHandshakeFailures[clientIP]
		tcpHandshakeFailuresMu.Unlock()
		log.Printf("[TCP] [%s] Invalid handshake (%d/%d).", clientIP, failCount, handshakeFailureLimit)
		if failCount >= handshakeFailureLimit {
			banIP(clientIP)
		}
		return
	}

	// Passed handshake => whitelist.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf("[TCP] [%s] Authenticated => whitelisted.", clientIP)

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

	// Forward the handshake data that we read.
	backendConn.Write(buf[:n])
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
		logTCPError("copying from client to backend", err)
		backend.Close()
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		logTCPError("copying from backend to client", err)
		client.Close()
	}()

	wg.Wait()
	log.Printf("[TCP] [%s] Connection closed.", clientIP)
}

// ------------------------
// UDP Proxy Logic
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

var (
	udpHandshakeChecked   = make(map[string]bool)
	udpHandshakeCheckedMu sync.Mutex
)

func hasCheckedHandshake(key string) bool {
	udpHandshakeCheckedMu.Lock()
	defer udpHandshakeCheckedMu.Unlock()
	return udpHandshakeChecked[key]
}

func markHandshakeChecked(key string) {
	udpHandshakeCheckedMu.Lock()
	udpHandshakeChecked[key] = true
	udpHandshakeCheckedMu.Unlock()
}

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

		atomic.AddUint64(&ddosPacketCount, 1)
		atomic.AddUint64(&ddosByteCount, uint64(n))

		clientKey := clientAddr.String()

		bannedIPsMu.RLock()
		if bannedIPs[clientAddr.IP.String()] {
			bannedIPsMu.RUnlock()
			continue
		}
		bannedIPsMu.RUnlock()

		// If already whitelisted, skip handshake checks or rate limiting
		if isWhitelisted(clientAddr.IP.String()) {
			forwardUDP(listenConn, backendAddr, clientKey, buf[:n])
			continue
		}

		// If under attack, block new IP
		if isDDoSActive() {
			log.Printf("[UDP] [%s] Blocked: DDoS active, new IP not whitelisted.", clientKey)
			continue
		}

		// If we've hit max new IPs, block
		if !canWhitelistNewIP() {
			log.Printf("[UDP] [%s] Blocked: Too many new IPs whitelisted recently.", clientKey)
			continue
		}

		// If not whitelisted and no handshake check yet, do it.
		if !hasCheckedHandshake(clientKey) {
			if !disableUDPHandshakeCheck {
				// Must pass isFiveMHandshake
				if !isFiveMHandshake(buf[:n]) {
					udpHandshakeFailuresMu.Lock()
					udpHandshakeFailures[clientKey]++
					failCount := udpHandshakeFailures[clientKey]
					udpHandshakeFailuresMu.Unlock()
					log.Printf("[UDP] [%s] Invalid handshake attempt (%d/%d).", clientKey, failCount, udpHandshakeFailureLimit)
					if failCount >= udpHandshakeFailureLimit {
						banIP(clientAddr.IP.String())
					}
					continue
				}
			}
			// Passed handshake => whitelist
			updateWhitelist(clientAddr.IP.String())
			markHandshakeChecked(clientKey)
			log.Printf("[UDP] [%s] Handshake authenticated => whitelisted.", clientKey)
		} else {
			// If handshake was never validated => ban
			log.Printf("[UDP] [%s] Missing handshake => banned.", clientKey)
			banIP(clientAddr.IP.String())
			continue
		}

		// Forward
		forwardUDP(listenConn, backendAddr, clientKey, buf[:n])
	}
}

func forwardUDP(listenConn *net.UDPConn, backendAddr *net.UDPAddr, clientKey string, data []byte) {
	sessionMu.Lock()
	sd, exists := sessionMap[clientKey]
	if !exists {
		backendConn, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			sessionMu.Unlock()
			log.Printf("[UDP] Error dialing backend for client %s: %v", clientKey, err)
			return
		}
		clientAddr, _ := net.ResolveUDPAddr("udp", clientKey)
		sd = &sessionData{
			clientAddr:  clientAddr,
			backendConn: backendConn,
			lastActive:  time.Now(),
		}
		sessionMap[clientKey] = sd
		go handleUDPSession(listenConn, sd)
	} else {
		sd.lastActive = time.Now()
	}
	sessionMu.Unlock()

	_, err := sd.backendConn.Write(data)
	if err != nil {
		log.Printf("[UDP] Write to backend error for client %s: %v", clientKey, err)
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
// DDoS Detection (Sliding Window)
// ------------------------

func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	const interval = 10 * time.Second
	const ddosWindowSize = 3
	const ppsThreshold = 1000.0
	const mbpsThreshold = 1.0

	var ppsWindow []float64
	var mbpsWindow []float64
	attackActiveLocal := false
	consecutiveBelow := 0

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		pps := float64(atomic.LoadUint64(&ddosPacketCount)) / 10.0
		bytesCount := atomic.LoadUint64(&ddosByteCount)
		mbps := (float64(bytesCount)*8/1e6)/10.0

		// Append new values
		if len(ppsWindow) >= ddosWindowSize {
			ppsWindow = ppsWindow[1:]
			mbpsWindow = mbpsWindow[1:]
		}
		ppsWindow = append(ppsWindow, pps)
		mbpsWindow = append(mbpsWindow, mbps)

		// Compute averages
		var sumPps, sumMbps float64
		for _, v := range ppsWindow {
			sumPps += v
		}
		for _, v := range mbpsWindow {
			sumMbps += v
		}
		avgPps := sumPps / float64(len(ppsWindow))
		avgMbps := sumMbps / float64(len(mbpsWindow))

		// Reset counters
		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)

		log.Printf("[DDoS Monitor] Avg PPS: %.2f, Avg Mbps: %.2f (Current: %.2f PPS, %.2f Mbps)", avgPps, avgMbps, pps, mbps)

		if avgPps > ppsThreshold || avgMbps > mbpsThreshold {
			if !attackActiveLocal {
				// Start mitigation
				setDDoSActive(true)
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP, targetPort)
				log.Printf("[DDoS Alert] Mitigation started: Attack detected (avgPPS: %.2f, avgMbps: %.2f)", avgPps, avgMbps)
				attackActiveLocal = true
			}
			consecutiveBelow = 0
		} else {
			if attackActiveLocal {
				consecutiveBelow++
				if consecutiveBelow >= 2 {
					// Attack subsided
					setDDoSActive(false)
					sendDDoSAttackEnded(discordWebhook, serverName, serverIP, targetPort)
					log.Printf("[DDoS Alert] Mitigation ended: Attack subsided (avgPPS: %.2f, avgMbps: %.2f)", avgPps, avgMbps)
					attackActiveLocal = false
					consecutiveBelow = 0
					ppsWindow = nil
					mbpsWindow = nil
				}
			}
		}
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

	log.Printf("[INFO] Starting proxy: forwarding to %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	// Start rate-limit resets
	go resetTCPCounts()
	go resetUDPPacketCounts()

	// Start TCP proxy
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

	// Start UDP proxy
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start the DDoS detection
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	// Block forever
	select {}
}

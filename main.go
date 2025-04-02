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

const disableDiscord = false         // Set to false to enable Discord notifications.
const disableUDPHandshakeCheck = true  // Set to true to disable UDP handshake check (if needed).

// discordEmbed defines the structure of a Discord embed.
type discordEmbed struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
}

// discordWebhookBody defines the structure of the webhook payload.
type discordWebhookBody struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

// sendDiscordEmbed sends a Discord embed message to the given webhook URL.
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

// sendDDoSAttackStarted sends a generic alert when a DDoS attack is detected.
func sendDDoSAttackStarted(webhookURL, serverName, serverIP, targetPort string) {
	title := "Perko's Proxy Alert"
	description := "Mitigation started: An attack on your server has been detected and is being mitigated."
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

// sendDDoSAttackEnded sends a generic alert when a DDoS attack subsides.
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

// updateWhitelist adds an IP to the whitelist.
func updateWhitelist(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

// isWhitelisted checks if an IP is whitelisted.
func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

// banIP adds an IP to the banned list.
func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
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

// TCP connection rate tracking.
var (
	connectionRates   = make(map[string]int)
	connectionRatesMu sync.Mutex
	tcpThreshold      = 10 // max allowed connections per 10 seconds
)

// UDP packet rate tracking.
var (
	udpPacketCounts   = make(map[string]int)
	udpPacketCountsMu sync.Mutex
	udpThreshold      = 500 // allowed UDP packets per 10 seconds for non-whitelisted clients
)

// resetTCPCounts clears the TCP connection counts every 10 seconds.
func resetTCPCounts() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		connectionRatesMu.Lock()
		connectionRates = make(map[string]int)
		connectionRatesMu.Unlock()
	}
}

// resetUDPPacketCounts clears the UDP packet counts every 10 seconds.
func resetUDPPacketCounts() {
	ticker := time.NewTicker(10 * time.Second)
	for range ticker.C {
		udpPacketCountsMu.Lock()
		udpPacketCounts = make(map[string]int)
		udpPacketCountsMu.Unlock()
	}
}

// ------------------------
// DDoS Global Counters (used for detection)
// ------------------------

var (
	ddosPacketCount uint64
	ddosByteCount   uint64
)

// ------------------------
// Logging Helpers
// ------------------------

// logTCPError logs TCP errors if they are not typical connection close/reset errors.
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

// isTCPHandshake checks for a basic TLS handshake header.
func isTCPHandshake(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03)
}

// isFiveMHandshake checks for known FiveM GET/POST patterns and common client signatures.
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

	// Immediately drop if the IP is banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
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

	// If already whitelisted, proxy immediately.
	if isWhitelisted(clientIP) {
		log.Printf("[TCP] [%s] Whitelisted: Connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Minimal handshake check.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
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

	// Validate handshake for FiveM.
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		tcpHandshakeFailuresMu.Lock()
		tcpHandshakeFailures[clientIP]++
		failCount := tcpHandshakeFailures[clientIP]
		tcpHandshakeFailuresMu.Unlock()
		log.Printf("[TCP] [%s] Invalid handshake (%d/%d)", clientIP, failCount, handshakeFailureLimit)
		if failCount >= handshakeFailureLimit {
			banIP(clientIP)
		}
		return
	}

	// Valid handshake: whitelist and proceed.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf("[TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	// Enable TCP keepalive.
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()

	// Forward handshake data.
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
	log.Printf("[TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic (with persistent sessions)
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

// UDP handshake tracking.
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

		// UDP handshake check: if not already whitelisted, verify handshake.
		if !isWhitelisted(clientAddr.IP.String()) && !hasCheckedHandshake(clientKey) {
			if !disableUDPHandshakeCheck {
				if !isFiveMHandshake(buf[:n]) {
					udpHandshakeFailuresMu.Lock()
					udpHandshakeFailures[clientKey]++
					failCount := udpHandshakeFailures[clientKey]
					udpHandshakeFailuresMu.Unlock()
					log.Printf("[UDP] [%s] Invalid handshake attempt (%d/%d)", clientKey, failCount, udpHandshakeFailureLimit)
					if failCount >= udpHandshakeFailureLimit {
						banIP(clientAddr.IP.String())
					}
					continue
				}
			}
			log.Printf("[UDP] [%s] Handshake authenticated – whitelisting", clientKey)
			updateWhitelist(clientAddr.IP.String())
			markHandshakeChecked(clientKey)
		} else if !isWhitelisted(clientAddr.IP.String()) {
			log.Printf("[UDP] [%s] Handshake missing – banning", clientKey)
			banIP(clientAddr.IP.String())
			continue
		}

		// Only apply UDP rate limiting for non-whitelisted clients.
		if !isWhitelisted(clientAddr.IP.String()) {
			udpPacketCountsMu.Lock()
			udpPacketCounts[clientKey]++
			if udpPacketCounts[clientKey] > udpThreshold {
				bannedIPsMu.Lock()
				bannedIPs[clientAddr.IP.String()] = true
				bannedIPsMu.Unlock()
				udpPacketCountsMu.Unlock()
				log.Printf("[UDP] [%s] Banned: Excessive packet rate", clientKey)
				continue
			}
			udpPacketCountsMu.Unlock()
		}

		// Create or update session.
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
// New DDoS Detection Logic
// ------------------------
// This new logic uses a sliding window (moving average) over 10-second intervals.
// It requires sustained high traffic before activating mitigation and ends after two consecutive low intervals.

func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	const interval = 10 * time.Second
	const ddosWindowSize = 3
	const ppsThreshold = 1000.0 // packets per second threshold
	const mbpsThreshold = 1.0   // Mbps threshold

	var ppsWindow []float64
	var mbpsWindow []float64
	attackActive := false
	consecutiveBelow := 0

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		pps := float64(atomic.LoadUint64(&ddosPacketCount)) / 10.0
		bytesCount := atomic.LoadUint64(&ddosByteCount)
		mbps := (float64(bytesCount)*8/1e6)/10.0

		// Append new values to the sliding window.
		if len(ppsWindow) >= ddosWindowSize {
			ppsWindow = ppsWindow[1:]
			mbpsWindow = mbpsWindow[1:]
		}
		ppsWindow = append(ppsWindow, pps)
		mbpsWindow = append(mbpsWindow, mbps)

		// Compute averages.
		var sumPps, sumMbps float64
		for _, v := range ppsWindow {
			sumPps += v
		}
		for _, v := range mbpsWindow {
			sumMbps += v
		}
		avgPps := sumPps / float64(len(ppsWindow))
		avgMbps := sumMbps / float64(len(mbpsWindow))

		// Reset counters.
		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)

		log.Printf("[DDoS Monitor] Avg PPS: %.2f, Avg Mbps: %.2f (Current: %.2f PPS, %.2f Mbps)", avgPps, avgMbps, pps, mbps)

		// If the moving averages exceed thresholds, detect an attack.
		if avgPps > ppsThreshold || avgMbps > mbpsThreshold {
			if !attackActive {
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP, targetPort)
				log.Printf("[DDoS Alert] Mitigation started: Attack detected (avgPPS: %.2f, avgMbps: %.2f)", avgPps, avgMbps)
				attackActive = true
			}
			consecutiveBelow = 0
		} else {
			if attackActive {
				consecutiveBelow++
				if consecutiveBelow >= 2 {
					sendDDoSAttackEnded(discordWebhook, serverName, serverIP, targetPort)
					log.Printf("[DDoS Alert] Mitigation ended: Attack subsided (avgPPS: %.2f, avgMbps: %.2f)", avgPps, avgMbps)
					attackActive = false
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

	// Start rate limit reset goroutines.
	go resetTCPCounts()
	go resetUDPPacketCounts()

	// Start TCP proxy.
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

	// Start UDP proxy.
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start the new, consolidated DDoS detection logic.
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	// Block forever.
	select {}
}

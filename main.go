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

// ---------------------------------------------------
// Discord Notification Structures & Functions
// ---------------------------------------------------

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
	if webhookURL == "" {
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

// sendDDoSAttackStarted sends an embed alert when a DDoS attack is detected.
func sendDDoSAttackStarted(
	webhookURL, serverName, serverIP, currentMetrics, attackMethod, targetPort string,
) {
	title := "FiveGate Proxy"
	description := ":rotating_light: DDoS Attack Started\n" +
		"A potential DDoS attack has been detected.\n\n" +
		fmt.Sprintf("**Server**\n%s - %s\n", serverName, serverIP) +
		fmt.Sprintf("**Attack Method**\n%s\n", attackMethod) +
		fmt.Sprintf("**Target Port**\n%s\n\n", targetPort) +
		fmt.Sprintf("**Current Metrics**\n%s\n", currentMetrics)

	// Red color
	sendDiscordEmbed(webhookURL, title, description, 0xFF0000)
}

// sendDDoSAttackEnded sends an embed alert when a DDoS attack ends.
func sendDDoSAttackEnded(
	webhookURL, serverName, serverIP, peakMetrics, firewallStats, attackMethod, targetPort string,
) {
	title := "FiveGate Proxy"
	description := ":white_check_mark: DDoS Attack Ended\n" +
		"The attack has ended. Final recorded metrics:\n\n" +
		fmt.Sprintf("**Server**\n%s - %s\n", serverName, serverIP) +
		fmt.Sprintf("**Attack Method**\n%s\n", attackMethod) +
		fmt.Sprintf("**Target Port**\n%s\n\n", targetPort) +
		fmt.Sprintf("**Peak Metrics**\n%s\n\n", peakMetrics) +
		fmt.Sprintf("**Firewall Stats**\n%s\n", firewallStats)

	// Green color
	sendDiscordEmbed(webhookURL, title, description, 0x00FF00)
}

// ---------------------------------------------------
// Global Variables for Whitelisting & Banning
// ---------------------------------------------------

var (
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex
)

// updateWhitelist marks an IP as whitelisted.
func updateWhitelist(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

// isWhitelisted checks if an IP is in the whitelist.
func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

// banIP marks an IP as banned.
func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// isBanned checks if an IP is banned.
func isBanned(ip string) bool {
	bannedIPsMu.RLock()
	defer bannedIPsMu.RUnlock()
	return bannedIPs[ip]
}

// ---------------------------------------------------
// TCP / UDP DDoS Counters
// ---------------------------------------------------

// We'll track separate counters for TCP and UDP traffic.
var (
	// TCP counters (connections per interval).
	tcpConnCount uint64

	// UDP counters (packets & bytes per interval).
	udpPacketCount uint64
	udpByteCount   uint64

	// A flag to mark if an attack is currently active.
	ddosAttackActive bool
	ddosMutex        sync.Mutex
)

// ---------------------------------------------------
// Basic Handshake Detection (for TCP/UDP Whitelisting)
// ---------------------------------------------------

// isLegitHandshake attempts to identify if the initial data from a client
// looks like a legitimate handshake (TLS, some typical GET/POST patterns, etc.).
func isLegitHandshake(data []byte) bool {
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03) {
		// TLS handshake
		return true
	}
	// Some quick textual checks for GET/POST
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client") {
		return true
	}
	return false
}

// ---------------------------------------------------
// TCP Proxy Logic
// ---------------------------------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort string) {
	defer conn.Close()
	clientAddr := conn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()

	if isBanned(clientIP) {
		log.Printf("[TCP] Dropped connection from banned IP %s", clientIP)
		return
	}

	// If already whitelisted, skip handshake check.
	if !isWhitelisted(clientIP) {
		// Try reading a small handshake
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.SetReadDeadline(time.Time{})
		if err != nil || n == 0 {
			log.Printf("[TCP] [%s] Error reading handshake: %v", clientIP, err)
			banIP(clientIP)
			return
		}

		if !isLegitHandshake(buf[:n]) {
			log.Printf("[TCP] [%s] Dropped - Invalid handshake", clientIP)
			banIP(clientIP)
			return
		}

		// Passed handshake checks; whitelist IP
		updateWhitelist(clientIP)

		// We also "consume" that read data and pass it along to the backend
		atomic.AddUint64(&tcpConnCount, 1)

		// Connect to backend
		backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
		if err != nil {
			log.Printf("[TCP] [%s] Backend connection error: %v", clientIP, err)
			return
		}
		defer backendConn.Close()

		// Write the handshake data we already read
		backendConn.Write(buf[:n])

		// Now proxy data in both directions
		proxyTCPWithConn(conn, backendConn, clientIP)
		return
	}

	// Already whitelisted
	atomic.AddUint64(&tcpConnCount, 1)
	log.Printf("[TCP] [%s] Whitelisted connection", clientIP)
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] [%s] Backend dial error: %v", clientIP, err)
		return
	}
	defer backendConn.Close()
	proxyTCPWithConn(conn, backendConn, clientIP)
}

// proxyTCPWithConn proxies data between client and backend.
func proxyTCPWithConn(client, backend net.Conn, clientIP string) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backend, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, backend)
		done <- struct{}{}
	}()

	<-done // wait for one side to close
	log.Printf("[TCP] [%s] Connection closed", clientIP)
}

// ---------------------------------------------------
// UDP Proxy Logic (with "Session" concept)
// ---------------------------------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastActive  time.Time
	closeOnce   sync.Once
}

var (
	sessionMap   = make(map[string]*sessionData)
	sessionMu    sync.Mutex
	sessionTTL   = 600 * time.Second  // 10 minutes
	cleanupTimer = 30 * time.Second   // how often we check for idle sessions
)

// startUDPProxy sets up a UDP listener and proxies packets to/from the target.
func startUDPProxy(listenPort, targetIP, targetPort string) {
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

	// Start background session cleanup
	go cleanupSessions()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP] Read error: %v", err)
			continue
		}

		// Count for DDoS detection
		atomic.AddUint64(&udpPacketCount, 1)
		atomic.AddUint64(&udpByteCount, uint64(n))

		clientIP := clientAddr.IP.String()
		if isBanned(clientIP) {
			log.Printf("[UDP] Dropped packet from banned IP %s", clientIP)
			continue
		}

		if !isWhitelisted(clientIP) {
			// Minimal handshake check
			if !isLegitHandshake(buf[:n]) {
				log.Printf("[UDP] Dropped packet from %s - invalid handshake", clientIP)
				banIP(clientIP)
				continue
			}
			updateWhitelist(clientIP)
			log.Printf("[UDP] [%s] Whitelisted via UDP handshake", clientIP)
		}

		sessionMu.Lock()
		sd, ok := sessionMap[clientAddr.String()]
		if !ok {
			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				sessionMu.Unlock()
				log.Printf("[UDP] Error dialing backend for client %s: %v", clientIP, err)
				continue
			}
			sd = &sessionData{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMap[clientAddr.String()] = sd
			// Start reading from backend -> client
			go handleUDPSession(listenConn, sd)
		} else {
			// Update last active
			sd.lastActive = time.Now()
		}
		sessionMu.Unlock()

		_, err = sd.backendConn.Write(buf[:n])
		if err != nil {
			log.Printf("[UDP] Write to backend error for client %s: %v", clientIP, err)
			continue
		}
	}
}

// handleUDPSession reads from the backend and writes to the client until closed.
func handleUDPSession(listenConn *net.UDPConn, sd *sessionData) {
	buf := make([]byte, 2048)
	for {
		sd.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sd.backendConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Just a read timeout, continue
				continue
			}
			log.Printf("[UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, werr := listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if werr != nil {
			log.Printf("[UDP] Error writing to client %s: %v", sd.clientAddr, werr)
		}
	}
	cleanupSession(sd.clientAddr.String())
}

// cleanupSessions periodically removes idle sessions.
func cleanupSessions() {
	ticker := time.NewTicker(cleanupTimer)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		sessionMu.Lock()
		for key, sd := range sessionMap {
			if now.Sub(sd.lastActive) > sessionTTL {
				log.Printf("[UDP] Closing idle session for client %s", sd.clientAddr)
				cleanupSession(key)
			}
		}
		sessionMu.Unlock()
	}
}

// cleanupSession closes and removes a session from the map.
func cleanupSession(key string) {
	sessionMu.Lock()
	sd, ok := sessionMap[key]
	if ok {
		delete(sessionMap, key)
		sd.closeOnce.Do(func() {
			sd.backendConn.Close()
		})
	}
	sessionMu.Unlock()
}

// ---------------------------------------------------
// DDoS Detection
// ---------------------------------------------------

// We'll track the peak rates, and a simple threshold check for each type.
// If either crosses threshold, we consider it a DDoS event.
func monitorDDoS(
	webhookURL string,
	serverName string,
	serverIP string,
	targetPort string,
) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Thresholds (tune as desired)
	const tcpConnThreshold = 100   // # of new TCP connections per 10s
	const udpPpsThreshold  = 1000  // # of UDP packets per second
	const udpMbpsThreshold = 1.0   // 1 Mbps over 10s => 10 Mb total in 10s

	var (
		peakTCPConnRate  uint64
		peakUDPPps       uint64
		peakUDPMbps      float64
		belowCount       int
	)

	for range ticker.C {
		// Grab the counters
		tcpCount := atomic.SwapUint64(&tcpConnCount, 0)
		udpCount := atomic.SwapUint64(&udpPacketCount, 0)
		udpBytes := atomic.SwapUint64(&udpByteCount, 0)

		// Connections per 10s => "connRate" = conn/s
		tcpConnRate := tcpCount / 10

		// UDP pps
		udpPps := udpCount / 10

		// UDP Mbps (megabits per second) over the 10s window
		udpMbps := (float64(udpBytes) * 8 / 1e6) / 10

		// Track peaks
		if tcpConnRate > peakTCPConnRate {
			peakTCPConnRate = tcpConnRate
		}
		if udpPps > peakUDPPps {
			peakUDPPps = udpPps
		}
		if udpMbps > peakUDPMbps {
			peakUDPMbps = udpMbps
		}

		// Decide if thresholds are exceeded
		tcpAttack := (tcpConnRate > tcpConnThreshold)
		udpAttack := (udpPps > udpPpsThreshold) || (udpMbps > udpMbpsThreshold)

		ddosMutex.Lock()
		switch {
		case tcpAttack || udpAttack:
			// Attack is happening
			if !ddosAttackActive {
				ddosAttackActive = true
				belowCount = 0

				attackMethod := detectAttackMethod(tcpAttack, udpAttack)
				currentMetrics := fmt.Sprintf(
					"TCP: %d conns/10s (rate %d/s)\nUDP: %d packets/10s (%d pps), %.2f Mbps",
					tcpCount, tcpConnRate,
					udpCount, udpPps, udpMbps,
				)
				sendDDoSAttackStarted(
					webhookURL,
					serverName,
					serverIP,
					currentMetrics,
					attackMethod,
					targetPort,
				)
			}
		default:
			// No attack
			if ddosAttackActive {
				belowCount++
				// Wait for 2 intervals below threshold to confirm attack ended
				if belowCount >= 2 {
					attackMethod := detectAttackMethod(true, true) // we can show "Mixed" or last known
					// Or do a simpler approach: pick "TCP" if we saw tcpAttack last time, etc.
					// For demonstration, we'll just show "Unknown or Mixed" if we can't track last method.
					attackMethod = "Unknown or Mixed"
					peak := fmt.Sprintf("Peak TCP: %d conn/s | Peak UDP: %d pps, %.2f Mbps",
						peakTCPConnRate, peakUDPPps, peakUDPMbps)
					firewallStats := "Unique IPs: TBD, Banned IPs: TBD"

					sendDDoSAttackEnded(
						webhookURL,
						serverName,
						serverIP,
						peak,
						firewallStats,
						attackMethod,
						targetPort,
					)
					ddosAttackActive = false
					belowCount = 0
					peakTCPConnRate = 0
					peakUDPPps = 0
					peakUDPMbps = 0
				}
			}
		}
		ddosMutex.Unlock()
	}
}

// detectAttackMethod tries to guess the method based on which thresholds are exceeded.
func detectAttackMethod(tcpAttack, udpAttack bool) string {
	switch {
	case tcpAttack && udpAttack:
		return "TCP & UDP Flood"
	case tcpAttack:
		return "TCP Flood"
	case udpAttack:
		return "UDP Flood"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------
// Main
// ---------------------------------------------------

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")

	// Additional flags for customizing the embed
	serverName := flag.String("serverName", "FiveGate", "Name of the server (for Discord embed)")
	serverIPFlag := flag.String("serverIP", "128.0.118.91", "Server IP (for Discord embed)")

	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL for alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr,
			"Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [options]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.Printf("[INFO] Starting FiveGate Proxy: forwarding to %s:%s, listening on port %s",
		*targetIP, *targetPort, *listenPort)

	// Start DDoS monitoring in the background
	go monitorDDoS(*discordWebhook, *serverName, *serverIPFlag, *targetPort)

	// Start TCP listener
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
			go handleTCPConnection(conn, *targetIP, *targetPort)
		}
	}()

	// Start UDP proxy (runs in main goroutine)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

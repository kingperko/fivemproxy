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

// Set this to true to disable Discord notifications (for now).
const disableDiscord = true

// Added flag to disable UDP handshake check.
const disableUDPHandshakeCheck = true

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
// Currently disabled until a later update.
func sendDiscordEmbed(webhookURL, title, description string, color int) {
	if disableDiscord {
		return
	}
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
		log.Printf(">> [DISCORD] JSON marshal error: %v", err)
		return
	}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf(">> [DISCORD] Request creation error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf(">> [DISCORD] Request error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf(">> [DISCORD] Unexpected status code: %d", resp.StatusCode)
	}
}

// sendDDoSAttackStarted sends an embed alert when a DDoS attack is detected.
func sendDDoSAttackStarted(webhookURL, serverName, serverIP, currentMetrics, attackMethod, targetPort string) {
	title := "Perko's Proxy"
	description := ":rotating_light: DDoS Attack Started\n" +
		"A potential DDoS attack has been detected.\n\n" +
		"**Server**\n" + serverName + " - " + serverIP + "\n" +
		"**Current Metrics**\n" + currentMetrics + "\n" +
		"**Attack Method**\n" + attackMethod + "\n" +
		"**Target Port**\n" + targetPort
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

// sendDDoSAttackEnded sends an embed alert when a DDoS attack ends.
func sendDDoSAttackEnded(webhookURL, serverName, serverIP, peakMetrics, firewallStats, attackMethod, targetPort string) {
	title := "Perko's Proxy"
	description := ":white_check_mark: DDoS Attack Ended\n" +
		"The attack has ended. Final recorded metrics:\n\n" +
		"**Server**\n" + serverName + " - " + serverIP + "\n" +
		"**Peak Metrics**\n" + peakMetrics + "\n" +
		"**Firewall Stats**\n" + firewallStats + "\n" +
		"**Attack Method**\n" + attackMethod + "\n" +
		"**Target Port**\n" + targetPort
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
// Rate Limiting for DDoS Prevention
// ------------------------

// For TCP: track connection attempts per IP.
var (
	connectionRates   = make(map[string]int)
	connectionRatesMu sync.Mutex
	tcpThreshold      = 10 // max allowed connections per 10 seconds
)

// For UDP: track packet counts per IP.
var (
	udpPacketCounts   = make(map[string]int)
	udpPacketCountsMu sync.Mutex
	udpThreshold      = 500 // increased threshold for legitimate traffic bursts
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
// DDoS Global Variables
// ------------------------

var (
	ddosMutex        sync.Mutex
	ddosPacketCount  uint64
	ddosByteCount    uint64
	ddosAttackActive bool
)

// ------------------------
// Logging Helpers
// ------------------------

// logTCPError logs TCP errors only if they are not common closed/connection-reset errors.
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
	log.Printf(">> [TCP] %s: %v", prefix, err)
}

// ------------------------
// Handshake Detection
// ------------------------

// isTCPHandshake checks for a basic TLS handshake header.
func isTCPHandshake(data []byte) bool {
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
	return false
}

// isFiveMHandshake checks for known FiveM GET/POST patterns.
func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client") {
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

	// If the IP is banned, drop the connection.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		return
	}
	bannedIPsMu.RUnlock()

	// Rate limit: count each new connection.
	connectionRatesMu.Lock()
	connectionRates[clientIP]++
	if connectionRates[clientIP] > tcpThreshold {
		bannedIPsMu.Lock()
		bannedIPs[clientIP] = true
		bannedIPsMu.Unlock()
		connectionRatesMu.Unlock()
		log.Printf(">> [TCP] [%s] Banned due to excessive connection attempts", clientIP)
		return
	}
	connectionRatesMu.Unlock()

	// If IP is already whitelisted, proxy immediately.
	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Minimal handshake check for new IP.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf(">> [TCP] [%s] Error reading handshake: %v", clientIP, err)
		banIP(clientIP)
		return
	}

	// Must pass either the TLS handshake check or known FiveM patterns.
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Dropped - Invalid handshake", clientIP)
		banIP(clientIP)
		return
	}

	// Good handshake => whitelist.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	// Enable TCP keepalive on backend connection.
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()

	// Forward the handshake data.
	backendConn.Write(buf[:n])
	proxyTCPWithConn(conn, backendConn, clientIP)
}

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] Backend dial error: %v", err)
		return
	}
	// Enable TCP keepalive on backend connection.
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()
	proxyTCPWithConn(client, backendConn, client.RemoteAddr().String())
}

// proxyTCPWithConn forwards data between client and backend using two goroutines.
func proxyTCPWithConn(client, backend net.Conn, clientIP string) {
	// Enable TCP keepalive on client connection if possible.
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from client to backend.
	go func() {
		defer wg.Done()
		_, err := io.Copy(backend, client)
		logTCPError("Error copying from client to backend", err)
		backend.Close()
	}()

	// Copy from backend to client.
	go func() {
		defer wg.Done()
		_, err := io.Copy(client, backend)
		logTCPError("Error copying from backend to client", err)
		client.Close()
	}()

	wg.Wait()
	log.Printf(">> [TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic (Persistent Sessions with Handshake Check)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr // Client address.
	backendConn *net.UDPConn // Persistent connection to backend for this client.
	lastActive  time.Time    // Last time this session was used.
	closeOnce   sync.Once    // Ensures cleanup is done only once.
}

var (
	sessionMap = make(map[string]*sessionData)
	sessionMu  sync.Mutex
)

// For UDP handshake tracking.
var (
	udpHandshakeChecked   = make(map[string]bool)
	udpHandshakeCheckedMu sync.Mutex
)

func hasCheckedHandshake(ip string) bool {
	udpHandshakeCheckedMu.Lock()
	defer udpHandshakeCheckedMu.Unlock()
	return udpHandshakeChecked[ip]
}

func markHandshakeChecked(ip string) {
	udpHandshakeCheckedMu.Lock()
	udpHandshakeChecked[ip] = true
	udpHandshakeCheckedMu.Unlock()
}

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	listenAddr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving listen address: %v", err)
	}
	listenConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatalf(">> [UDP] Error starting UDP listener on port %s: %v", listenPort, err)
	}
	log.Printf(">> [UDP] Listening on port %s", listenPort)

	backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving backend address: %v", err)
	}

	// Start DDoS monitoring.
	go monitorDDoS(discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", targetIP, listenPort), targetPort)

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			// Minimal logging to avoid console spam.
			continue
		}

		// Update global DDoS counters.
		atomic.AddUint64(&ddosPacketCount, 1)
		atomic.AddUint64(&ddosByteCount, uint64(n))

		clientIP := clientAddr.IP.String()

		// Rate limit for UDP packets.
		udpPacketCountsMu.Lock()
		udpPacketCounts[clientIP]++
		if udpPacketCounts[clientIP] > udpThreshold {
			bannedIPsMu.Lock()
			bannedIPs[clientIP] = true
			bannedIPsMu.Unlock()
			udpPacketCountsMu.Unlock()
			log.Printf(">> [UDP] [%s] Banned due to excessive packet rate", clientIP)
			continue
		}
		udpPacketCountsMu.Unlock()

		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			continue
		}
		bannedIPsMu.RUnlock()

		// Handshake check (unless disabled).
		if !isWhitelisted(clientIP) && !hasCheckedHandshake(clientIP) {
			if !disableUDPHandshakeCheck {
				if !isFiveMHandshake(buf[:n]) {
					log.Printf(">> [UDP] [%s] Dropped - invalid handshake, banning IP", clientIP)
					banIP(clientIP)
					continue
				}
			}
			log.Printf(">> [UDP] [%s] Authenticated handshake (or bypassed) => whitelisted", clientIP)
			updateWhitelist(clientIP)
			markHandshakeChecked(clientIP)
		} else if !isWhitelisted(clientIP) {
			log.Printf(">> [UDP] [%s] No handshake pass => ban", clientIP)
			banIP(clientIP)
			continue
		}

		// Normal flow: IP is whitelisted.
		sessionMu.Lock()
		sd, exists := sessionMap[clientAddr.String()]
		if !exists {
			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				sessionMu.Unlock()
				log.Printf(">> [UDP] Error dialing backend for client %s: %v", clientIP, err)
				continue
			}
			sd = &sessionData{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMap[clientAddr.String()] = sd
			go handleUDPSession(listenConn, sd)
		} else {
			sd.lastActive = time.Now()
		}
		sessionMu.Unlock()

		_, err = sd.backendConn.Write(buf[:n])
		if err != nil {
			log.Printf(">> [UDP] Write to backend error for client %s: %v", clientIP, err)
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
			log.Printf(">> [UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil {
			log.Printf(">> [UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
	// Keep connection alive until the client truly disconnects.
}

// ------------------------
// DDoS Detection Logic
// ------------------------

func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var peakPPS uint64
	var peakMbps float64
	var belowCount int

	// Set thresholds (adjust these as needed).
	const ppsThreshold = 1000 // packets per second threshold
	const mbpsThreshold = 1.0 // Mbps threshold

	for range ticker.C {
		pps := atomic.LoadUint64(&ddosPacketCount) / 10
		bytesCount := atomic.LoadUint64(&ddosByteCount)
		mbps := (float64(bytesCount)*8/1e6)/10

		if pps > peakPPS {
			peakPPS = pps
		}
		if mbps > peakMbps {
			peakMbps = mbps
		}

		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)

		ddosMutex.Lock()
		if pps > ppsThreshold || mbps > mbpsThreshold {
			if !ddosAttackActive {
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP,
					fmt.Sprintf(":zap: %d PPS | :electric_plug: %.2f Mbps", pps, mbps),
					"UDP Flood", targetPort)
				ddosAttackActive = true
			}
			belowCount = 0
		} else {
			if ddosAttackActive {
				belowCount++
				if belowCount >= 2 { // 20 seconds below threshold.
					sendDDoSAttackEnded(discordWebhook, serverName, serverIP,
						fmt.Sprintf(":zap: %d PPS | :electric_plug: %.2f Mbps", peakPPS, peakMbps),
						"Unique IPs: TBD, Banned IPs: TBD", "UDP Flood", targetPort)
					ddosAttackActive = false
					peakPPS = 0
					peakMbps = 0
					belowCount = 0
				}
			}
		}
		ddosMutex.Unlock()
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

	log.Printf(">> [INFO] Starting proxy: forwarding to %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	// Start rate limit reset goroutines.
	go resetTCPCounts()
	go resetUDPPacketCounts()

	// Start TCP proxy in a goroutine.
	go func() {
		ln, err := net.Listen("tcp", ":"+*listenPort)
		if err != nil {
			log.Fatalf(">> [TCP] Listen error on port %s: %v", *listenPort, err)
		}
		defer ln.Close()
		log.Printf(">> [TCP] Listening on port %s", *listenPort)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf(">> [TCP] Accept error: %v", err)
				continue
			}
			go handleTCPConnection(conn, *targetIP, *targetPort, *discordWebhook)
		}
	}()

	// Start UDP proxy in a separate goroutine.
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start DDoS monitoring in its own goroutine.
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	// Block forever.
	select {}
}

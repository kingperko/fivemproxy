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
// DDoS Global Variables
// ------------------------

var (
	ddosMutex        sync.Mutex
	ddosPacketCount  uint64
	ddosByteCount    uint64
	ddosAttackActive bool
)

// ------------------------
// Handshake Detection (For TCP only)
// ------------------------

func isLegitHandshake(data []byte) bool {
	// For TCP, we require a basic TLS handshake pattern.
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
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

	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf(">> [TCP] Dropped connection from banned IP %s", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf(">> [TCP] [%s] Error reading handshake: %v", clientIP, err)
		banIP(clientIP)
		return
	}

	if !isLegitHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Dropped - Invalid handshake", clientIP)
		banIP(clientIP)
		return
	}

	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	defer backendConn.Close()

	backendConn.Write(buf[:n])
	proxyTCPWithConn(conn, backendConn, clientIP)
}

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] Backend dial error: %v", err)
		return
	}
	defer backendConn.Close()
	proxyTCPWithConn(client, backendConn, client.RemoteAddr().String())
}

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
	<-done
	log.Printf(">> [TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic (Persistent Sessions)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr // Client address
	backendConn *net.UDPConn // Persistent connection to backend for this client
	lastActive  time.Time    // Last time this session was used
	closeOnce   sync.Once    // Ensures cleanup is done only once
}

var (
	// Keep legitimate sessions active for up to 600 seconds (10 minutes)
	sessionMap   = make(map[string]*sessionData)
	sessionMu    sync.Mutex
	cleanupTimer = 30 * time.Second  // How frequently to check for idle sessions
	sessionTTL   = 600 * time.Second // Idle timeout duration (10 minutes)
)

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
	// Start session cleanup.
	go cleanupSessions()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf(">> [UDP] Read error: %v", err)
			continue
		}

		// Update global DDoS counters.
		atomic.AddUint64(&ddosPacketCount, 1)
		atomic.AddUint64(&ddosByteCount, uint64(n))

		clientIP := clientAddr.IP.String()

		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			log.Printf(">> [UDP] Dropped packet from banned IP %s", clientIP)
			continue
		}
		bannedIPsMu.RUnlock()

		// For UDP, immediately whitelist new clients.
		if !isWhitelisted(clientIP) {
			updateWhitelist(clientIP)
			log.Printf(">> [UDP] [%s] Whitelisted", clientIP)
		}

		// Update or create persistent session.
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
		// Update lastActive on backend response.
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil {
			log.Printf(">> [UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
	cleanupSession(sd.clientAddr.String())
}

func cleanupSessions() {
	ticker := time.NewTicker(cleanupTimer)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sessionMu.Lock()
		for key, sd := range sessionMap {
			if now.Sub(sd.lastActive) > sessionTTL {
				log.Printf(">> [UDP] Closing idle session for client %s", sd.clientAddr)
				cleanupSession(key)
			}
		}
		sessionMu.Unlock()
	}
}

func cleanupSession(key string) {
	sessionMu.Lock()
	sd, exists := sessionMap[key]
	if exists {
		delete(sessionMap, key)
		sd.closeOnce.Do(func() {
			sd.backendConn.Close()
		})
	}
	sessionMu.Unlock()
}

// ------------------------
// DDoS Detection Logic
// ------------------------

// monitorDDoS checks UDP traffic every 10 seconds and sends a Discord alert
// when traffic exceeds the thresholds, and another alert when traffic falls below.
func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var peakPPS uint64
	var peakMbps float64
	var belowCount int

	// Set thresholds for attack detection.
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
				if belowCount >= 2 { // 20 seconds below threshold
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
// Utility Functions
// ------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

	// Start UDP proxy in a goroutine.
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start DDoS monitoring.
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	// Block forever.
	select {}
}

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
	// Whitelisted IPs that passed handshake
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	// We do not ban or drop any IP; we just log them if suspicious.
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

func logBan(ip string) {
	// Instead of banning, just log that we "would have" banned them
	bannedIPsMu.Lock()
	if !bannedIPs[ip] {
		bannedIPs[ip] = true
	}
	bannedIPsMu.Unlock()
	log.Printf(">> [BAN-LOG] IP %s would be banned (but we skip).", ip)
}

// ------------------------
// DDoS Global Variables
// ------------------------

var (
	ddosMutex        sync.Mutex
	ddosPacketCount  uint64
	ddosByteCount    uint64
	ddosAttackActive bool

	newBansCounter    uint64
	newSessionCounter uint64
)

// isTCPHandshake checks for a minimal TLS handshake or known GET patterns
func isTCPHandshake(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x00 && data[2] <= 0x03)
}

// isFiveMHandshake checks for typical FiveM GET/POST patterns
func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client")
}

// ------------------------
// TCP Proxy Logic
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// If "banned," we just log it and skip
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf(">> [TCP] Connection from IP %s (marked banned). Dropping.", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Minimal handshake check for new IP
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf(">> [TCP] [%s] Error reading handshake: %v", clientIP, err)
		logBan(clientIP)
		atomic.AddUint64(&newBansCounter, 1)
		return
	}

	// Must pass either the TLS check or known FiveM GET/POST patterns
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Invalid handshake => ban log", clientIP)
		logBan(clientIP)
		atomic.AddUint64(&newBansCounter, 1)
		return
	}

	// Good handshake => whitelist
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	atomic.AddUint64(&newSessionCounter, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	defer backendConn.Close()

	// Forward the handshake data
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
// UDP Proxy Logic (One-Packet Handshake Check)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastActive  time.Time
	closeOnce   sync.Once
}

var (
	sessionMap   = make(map[string]*sessionData)
	sessionMu    sync.Mutex
	cleanupTimer = 30 * time.Second
	sessionTTL   = 600 * time.Second // 10 minutes
)

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

	go monitorDDoS(discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", targetIP, listenPort), targetPort)
	go cleanupSessions()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf(">> [UDP] Read error: %v", err)
			continue
		}

		// DDoS counters
		atomic.AddUint64(&ddosPacketCount, 1)
		atomic.AddUint64(&ddosByteCount, uint64(n))

		clientIP := clientAddr.IP.String()

		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			log.Printf(">> [UDP] Packet from IP %s (marked banned). Dropping.", clientIP)
			continue
		}
		bannedIPsMu.RUnlock()

		// If IP is not whitelisted and hasn't been handshake-checked, do so
		if !isWhitelisted(clientIP) && !hasCheckedHandshake(clientIP) {
			if !isFiveMHandshake(buf[:n]) {
				log.Printf(">> [UDP] [%s] Invalid handshake => ban log", clientIP)
				logBan(clientIP)
				atomic.AddUint64(&newBansCounter, 1)
				markHandshakeChecked(clientIP)
				continue
			}
			// Pass
			log.Printf(">> [UDP] [%s] Handshake passed => whitelisted", clientIP)
			updateWhitelist(clientIP)
			markHandshakeChecked(clientIP)
			atomic.AddUint64(&newSessionCounter, 1)
		}

		// Normal flow
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

func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	var peakPPS uint64
	var peakMbps float64
	var belowCount int

	// Very low thresholds so "any traffic" triggers logs:
	const ppsThreshold = 1    // packets per second
	const mbpsThreshold = 0.01 // 0.01 Mbps
	const bansThreshold = 1   // new "bans" (really just logs)
	const sessionsThreshold = 1 // new sessions

	for range ticker.C {
		pps := atomic.LoadUint64(&ddosPacketCount) / 10
		bytesCount := atomic.LoadUint64(&ddosByteCount)
		mbps := (float64(bytesCount) * 8 / 1e6) / 10

		newBans := atomic.LoadUint64(&newBansCounter)
		newSessions := atomic.LoadUint64(&newSessionCounter)

		if pps > peakPPS {
			peakPPS = pps
		}
		if mbps > peakMbps {
			peakMbps = mbps
		}

		// Reset counters for the next interval
		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)
		atomic.StoreUint64(&newBansCounter, 0)
		atomic.StoreUint64(&newSessionCounter, 0)

		ddosMutex.Lock()
		// If ANY of these exceed the super-low thresholds, we call it an "attack"
		if pps > ppsThreshold || mbps > mbpsThreshold || newBans >= bansThreshold || newSessions >= sessionsThreshold {
			if !ddosAttackActive {
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP,
					fmt.Sprintf(":zap: %d PPS | :electric_plug: %.2f Mbps\nNew Bans: %d, New Sessions: %d", pps, mbps, newBans, newSessions),
					"UDP Flood", targetPort)
				ddosAttackActive = true
			}
			belowCount = 0
		} else {
			// If we were in an attack state but now below thresholds
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

		// Nicer debug logs in console
		log.Printf("[DEBUG] DDoS Monitor => PPS: %d, Mbps: %.2f, NewBans: %d, NewSessions: %d, AttackActive: %v",
			pps, mbps, newBans, newSessions, ddosAttackActive)
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

	// Start DDoS monitoring with extremely low thresholds so ANY traffic triggers logs.
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	// Block forever.
	select {}
}

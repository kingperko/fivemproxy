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

const disableDiscord = false
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

// trustedIPs holds IPs that are always allowed.
var (
	trustedIPs   = make(map[string]bool)
	trustedIPsMu sync.RWMutex
)

func isTrusted(ip string) bool {
	trustedIPsMu.RLock()
	defer trustedIPsMu.RUnlock()
	return trustedIPs[ip]
}

func addTrustedIPs(ips []string) {
	trustedIPsMu.Lock()
	defer trustedIPsMu.Unlock()
	for _, ip := range ips {
		if trimmed := strings.TrimSpace(ip); trimmed != "" {
			trustedIPs[trimmed] = true
		}
	}
}

// Tracks if we are under DDoS
var (
	ddosAttackActive bool
	ddosMutex        sync.RWMutex
)

func isDDoSActive() bool {
	ddosMutex.RLock()
	defer ddosMutex.RUnlock()
	return ddosAttackActive
}

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
	log.Printf("[WHITELIST] IP %s is now whitelisted.", ip)
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

func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))
	fivemRoute := strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client")
	fivemUserAgent := strings.Contains(lower, "user-agent: citizenfx") ||
		strings.Contains(lower, "user-agent: fxserver") ||
		strings.Contains(lower, "citizenfx")

	return fivemRoute && fivemUserAgent
}

func isTLSHandshake(data []byte) bool {
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
	return false
}

// ------------------------
// Two-Phase TCP Proxy Logic
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Trusted IPs bypass all checks.
	if isTrusted(clientIP) {
		updateWhitelist(clientIP)
		log.Printf("[TCP] [%s] Trusted IP => connection allowed.", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Immediately drop if banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf("[TCP] [%s] Connection from banned IP dropped.", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	// Simple connection rate limit.
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

	// If already whitelisted, skip handshake logic.
	if isWhitelisted(clientIP) {
		log.Printf("[TCP] [%s] Whitelisted => connection allowed.", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// If under active DDoS, block new IP.
	if isDDoSActive() {
		log.Printf("[TCP] [%s] Blocked: DDoS active, new IP not whitelisted.", clientIP)
		return
	}

	// PHASE 1: Basic handshake read.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
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

	// Must be either a recognized FiveM handshake or a TLS handshake.
	if !isFiveMHandshake(buf[:n]) && !isTLSHandshake(buf[:n]) {
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

	// PHASE 2: Forward handshake to backend and wait for initial response.
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] [%s] Backend dial error: %v", clientIP, err)
		return
	}
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Send handshake data to backend.
	_, err = backendConn.Write(buf[:n])
	if err != nil {
		log.Printf("[TCP] [%s] Error forwarding handshake to backend: %v", clientIP, err)
		backendConn.Close()
		return
	}

	// Wait for backend's initial response (7s timeout).
	backendConn.SetReadDeadline(time.Now().Add(7 * time.Second))
	respBuf := make([]byte, 4096)
	rn, rerr := backendConn.Read(respBuf)
	backendConn.SetReadDeadline(time.Time{})
	if rerr != nil || rn < 10 {
		log.Printf("[TCP] [%s] Backend response too short or error (rn: %d, err: %v) => banning IP.", clientIP, rn, rerr)
		banIP(clientIP)
		backendConn.Close()
		return
	}

	// Finalize whitelisting.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf("[TCP] [%s] Authenticated => whitelisted (phase 2).", clientIP)

	// Forward backend's response to the client.
	_, _ = conn.Write(respBuf[:rn])

	// Bridge remaining traffic.
	go func() {
		defer backendConn.Close()
		_, err := io.Copy(backendConn, conn)
		logTCPError("copying from client to backend", err)
	}()

	go func() {
		defer conn.Close()
		_, err := io.Copy(conn, backendConn)
		logTCPError("copying from backend to client", err)
	}()

	// Block until connection closes.
	select {}
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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, client)
		backendConn.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, backendConn)
		client.Close()
	}()

	wg.Wait()
}

// ------------------------
// Two-Phase UDP Proxy Logic
// ------------------------
//
// For UDP, if the IP is already whitelisted, packets are forwarded immediately.
// For new IPs, we attempt a mini two-phase handshake: forward the packet to backend,
// wait for up to 3 seconds for a response, and if a valid response is received, whitelist the IP.
type sessionDataUDP struct {
	clientAddr  *net.UDPAddr
	backendConn *net.UDPConn
	lastActive  time.Time
}

var (
	sessionMapUDP = make(map[string]*sessionDataUDP)
	sessionMuUDP  sync.Mutex

	udpHandshakeChecked   = make(map[string]bool)
	udpHandshakeCheckedMu sync.Mutex
)

func hasUDPCheckedHandshake(key string) bool {
	udpHandshakeCheckedMu.Lock()
	defer udpHandshakeCheckedMu.Unlock()
	return udpHandshakeChecked[key]
}

func markUDPCheckedHandshake(key string) {
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

		clientIP := clientAddr.IP.String()

		// Trusted IPs bypass UDP checks.
		if isTrusted(clientIP) {
			forwardUDP(listenConn, backendAddr, clientAddr, buf[:n])
			continue
		}

		// If banned, ignore.
		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			continue
		}
		bannedIPsMu.RUnlock()

		// Already whitelisted => forward UDP immediately.
		if isWhitelisted(clientIP) {
			forwardUDP(listenConn, backendAddr, clientAddr, buf[:n])
			continue
		}

		// If under attack, block new IP.
		if isDDoSActive() {
			log.Printf("[UDP] [%s] Blocked: DDoS active, new IP not whitelisted.", clientAddr.String())
			continue
		}

		// If we haven't done a handshake check yet, attempt UDP two-phase handshake.
		if !hasUDPCheckedHandshake(clientAddr.String()) {
			if !disableUDPHandshakeCheck {
				if !isFiveMHandshake(buf[:n]) {
					udpHandshakeFailuresMu.Lock()
					udpHandshakeFailures[clientAddr.String()]++
					failCount := udpHandshakeFailures[clientAddr.String()]
					udpHandshakeFailuresMu.Unlock()
					log.Printf("[UDP] [%s] Invalid handshake attempt (%d/%d).", clientAddr.String(), failCount, udpHandshakeFailureLimit)
					if failCount >= udpHandshakeFailureLimit {
						banIP(clientIP)
					}
					continue
				}
			}

			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				log.Printf("[UDP] [%s] Error dialing backend: %v", clientAddr.String(), err)
				continue
			}

			// Send the initial packet to backend.
			_, werr := backendConn.Write(buf[:n])
			if werr != nil {
				log.Printf("[UDP] [%s] Error forwarding handshake to backend: %v", clientAddr.String(), werr)
				backendConn.Close()
				continue
			}

			backendConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			respBuf := make([]byte, 2048)
			rn, rerr := backendConn.Read(respBuf)
			backendConn.SetReadDeadline(time.Time{})

			if rerr != nil || rn < 1 {
				log.Printf("[UDP] [%s] No backend response => banning IP.", clientAddr.String())
				banIP(clientIP)
				backendConn.Close()
				continue
			}

			updateWhitelist(clientIP)
			markUDPCheckedHandshake(clientAddr.String())
			log.Printf("[UDP] [%s] Authenticated => whitelisted.", clientAddr.String())
			_, _ = listenConn.WriteToUDP(respBuf[:rn], clientAddr)

			sessionMuUDP.Lock()
			sd := &sessionDataUDP{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMapUDP[clientAddr.String()] = sd
			sessionMuUDP.Unlock()
			go handleUDPSession(listenConn, sd)
			continue
		} else {
			// If handshake check was done but not whitelisted, ban.
			log.Printf("[UDP] [%s] Already handshake-checked => banning.", clientAddr.String())
			banIP(clientIP)
			continue
		}
	}
}

func forwardUDP(listenConn *net.UDPConn, backendAddr *net.UDPAddr, clientAddr *net.UDPAddr, data []byte) {
	sessionMuUDP.Lock()
	key := clientAddr.String()
	sd, exists := sessionMapUDP[key]
	if !exists {
		backendConn, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			sessionMuUDP.Unlock()
			log.Printf("[UDP] Error dialing backend for client %s: %v", key, err)
			return
		}
		sd = &sessionDataUDP{
			clientAddr:  clientAddr,
			backendConn: backendConn,
			lastActive:  time.Now(),
		}
		sessionMapUDP[key] = sd
		go handleUDPSession(listenConn, sd)
	} else {
		sd.lastActive = time.Now()
	}
	sessionMuUDP.Unlock()

	_, err := sd.backendConn.Write(data)
	if err != nil {
		log.Printf("[UDP] Write to backend error for client %s: %v", key, err)
	}
}

func handleUDPSession(listenConn *net.UDPConn, sd *sessionDataUDP) {
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
		sessionMuUDP.Lock()
		sd.lastActive = time.Now()
		sessionMuUDP.Unlock()
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

		if len(ppsWindow) >= ddosWindowSize {
			ppsWindow = ppsWindow[1:]
			mbpsWindow = mbpsWindow[1:]
		}
		ppsWindow = append(ppsWindow, pps)
		mbpsWindow = append(mbpsWindow, mbps)

		var sumPps, sumMbps float64
		for _, v := range ppsWindow {
			sumPps += v
		}
		for _, v := range mbpsWindow {
			sumMbps += v
		}
		avgPps := sumPps / float64(len(ppsWindow))
		avgMbps := sumMbps / float64(len(mbpsWindow))

		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)

		log.Printf("[DDoS Monitor] Avg PPS: %.2f, Avg Mbps: %.2f (Current: %.2f PPS, %.2f Mbps)",
			avgPps, avgMbps, pps, mbps)

		if avgPps > ppsThreshold || avgMbps > mbpsThreshold {
			if !attackActiveLocal {
				setDDoSActive(true)
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP, targetPort)
				log.Printf("[DDoS Alert] Mitigation started: Attack detected (avgPPS: %.2f, avgMbps: %.2f)",
					avgPps, avgMbps)
				attackActiveLocal = true
			}
			consecutiveBelow = 0
		} else {
			if attackActiveLocal {
				consecutiveBelow++
				if consecutiveBelow >= 2 {
					setDDoSActive(false)
					sendDDoSAttackEnded(discordWebhook, serverName, serverIP, targetPort)
					log.Printf("[DDoS Alert] Mitigation ended: Attack subsided (avgPPS: %.2f, avgMbps: %.2f)",
						avgPps, avgMbps)
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
	trustedIPsFlag := flag.String("trustedIPs", "", "Comma-separated list of trusted IPs that always connect")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>] [-trustedIPs=<ip1,ip2,...>]\n", os.Args[0])
		os.Exit(1)
	}

	// Parse trusted IPs, if provided.
	if *trustedIPsFlag != "" {
		ips := strings.Split(*trustedIPsFlag, ",")
		addTrustedIPs(ips)
	}

	log.Printf("[INFO] Starting proxy: forwarding to %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	go resetTCPCounts()
	go resetUDPPacketCounts()

	// Start TCP proxy (two-phase handshake)
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

	// Start UDP proxy with two-phase approach
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start DDoS detection
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	select {}
}

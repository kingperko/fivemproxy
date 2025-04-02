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

// trustedIPs holds IPs that must always be allowed.
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
// Smart Queue for New IPs (TCP)
// ------------------------

const maxNewIPsConcurrency = 5
var newIPsSemaphore = make(chan struct{}, maxNewIPsConcurrency)

func acquireNewIPSlot() {
	newIPsSemaphore <- struct{}{}
}

func releaseNewIPSlot() {
	<-newIPsSemaphore
}

// ------------------------
// Three-Phase TCP Proxy Logic
// ------------------------
//
// Phase 1: minimal handshake read
// Phase 2: forward to backend, require >=10 bytes response
// Phase 3: wait up to 3s for *more* data from the client. If none, ban (likely a fake partial handshake).

// We track whether we've seen "follow-up" data from the client after the initial handshake.
type tcpClientTracker struct {
	hasFollowUp bool
	mu          sync.Mutex
}

var tcpTrackerMap = make(map[string]*tcpClientTracker)
var tcpTrackerMu sync.Mutex

func getTCPTracker(ip string) *tcpClientTracker {
	tcpTrackerMu.Lock()
	defer tcpTrackerMu.Unlock()
	tracker, ok := tcpTrackerMap[ip]
	if !ok {
		tracker = &tcpClientTracker{}
		tcpTrackerMap[ip] = tracker
	}
	return tracker
}

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Trusted IPs skip everything.
	if isTrusted(clientIP) {
		updateWhitelist(clientIP)
		log.Printf("[TCP] [%s] Trusted => immediate pass-through.", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Banned => drop.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf("[TCP] [%s] Banned => dropped.", clientIP)
		conn.Close()
		return
	}
	bannedIPsMu.RUnlock()

	// Already whitelisted => skip concurrency & handshake checks.
	if isWhitelisted(clientIP) {
		log.Printf("[TCP] [%s] Whitelisted => connection allowed.", clientIP)
		go proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Acquire concurrency slot for new IP.
	acquireNewIPSlot()
	defer releaseNewIPSlot()

	// Rate limiting
	connectionRatesMu.Lock()
	connectionRates[clientIP]++
	if connectionRates[clientIP] > tcpThreshold {
		bannedIPsMu.Lock()
		bannedIPs[clientIP] = true
		bannedIPsMu.Unlock()
		connectionRatesMu.Unlock()
		log.Printf("[TCP] [%s] Banned: Excessive connection attempts", clientIP)
		conn.Close()
		return
	}
	connectionRatesMu.Unlock()

	// Phase 1: minimal handshake read
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
		conn.Close()
		return
	}

	if !isFiveMHandshake(buf[:n]) && !isTLSHandshake(buf[:n]) {
		tcpHandshakeFailuresMu.Lock()
		tcpHandshakeFailures[clientIP]++
		failCount := tcpHandshakeFailures[clientIP]
		tcpHandshakeFailuresMu.Unlock()
		log.Printf("[TCP] [%s] Invalid handshake (%d/%d).", clientIP, failCount, handshakeFailureLimit)
		if failCount >= handshakeFailureLimit {
			banIP(clientIP)
		}
		conn.Close()
		return
	}

	// Phase 2: forward to backend, require >= 10 bytes
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] [%s] Backend dial error: %v", clientIP, err)
		conn.Close()
		return
	}
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	_, err = backendConn.Write(buf[:n])
	if err != nil {
		log.Printf("[TCP] [%s] Error forwarding handshake: %v", clientIP, err)
		backendConn.Close()
		conn.Close()
		return
	}

	backendConn.SetReadDeadline(time.Now().Add(7 * time.Second))
	respBuf := make([]byte, 4096)
	rn, rerr := backendConn.Read(respBuf)
	backendConn.SetReadDeadline(time.Time{})
	if rerr != nil || rn < 10 {
		log.Printf("[TCP] [%s] Backend response too short/error => ban IP (rn=%d, err=%v).", clientIP, rn, rerr)
		banIP(clientIP)
		backendConn.Close()
		conn.Close()
		return
	}

	// Phase 3: We now do a "follow-up" check. We'll watch for 3 seconds if the client sends more data.
	// If they don't send anything else at all, it's suspicious => ban them. Real FiveM clients typically
	// keep sending more requests (like GET /players.json).
	tracker := getTCPTracker(clientIP)
	tracker.mu.Lock()
	tracker.hasFollowUp = false
	tracker.mu.Unlock()

	// Start bridging in a special way that monitors if the client sends additional data
	doneChan := make(chan struct{})
	go func() {
		defer close(doneChan)
		_, err := io.Copy(backendConn, &monitorReader{
			Reader:  conn,
			tracker: tracker,
		})
		logTCPError("copy from client to backend", err)
		backendConn.Close()
	}()

	go func() {
		_, err := io.Copy(conn, backendConn)
		logTCPError("copy from backend to client", err)
		conn.Close()
	}()

	// Send the initial response from the backend to the client.
	_, _ = conn.Write(respBuf[:rn])

	// Wait 3 seconds for follow-up data from the client.
	select {
	case <-doneChan:
		// The connection closed quickly; check if no follow-up was ever sent
		tracker.mu.Lock()
		if !tracker.hasFollowUp {
			// Ban
			log.Printf("[TCP] [%s] No follow-up data => ban IP (likely a fake partial handshake).", clientIP)
			banIP(clientIP)
		}
		tracker.mu.Unlock()
	case <-time.After(3 * time.Second):
		// The bridging is still open. That means the client is likely sending data or at least connected.
		tracker.mu.Lock()
		if !tracker.hasFollowUp {
			// The client might send data a bit later, so let's not ban immediately. We'll just whitelist them.
			updateWhitelist(clientIP)
			atomic.AddInt64(&tcpConnCount, 1)
			log.Printf("[TCP] [%s] Authenticated => whitelisted (phase 3, no immediate follow-up but still connected).", clientIP)
		} else {
			// They already sent follow-up => definitely real
			updateWhitelist(clientIP)
			atomic.AddInt64(&tcpConnCount, 1)
			log.Printf("[TCP] [%s] Authenticated => whitelisted (phase 3, follow-up seen).", clientIP)
		}
		tracker.mu.Unlock()
	}
}

// monitorReader is a wrapper that notes if the client sends additional data after the initial handshake.
type monitorReader struct {
	Reader  io.Reader
	tracker *tcpClientTracker
}

func (mr *monitorReader) Read(p []byte) (int, error) {
	n, err := mr.Reader.Read(p)
	if n > 0 {
		mr.tracker.mu.Lock()
		mr.tracker.hasFollowUp = true
		mr.tracker.mu.Unlock()
	}
	return n, err
}

// ------------------------
// Standard bridging for an already whitelisted or trusted IP
// ------------------------

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Backend dial error: %v", err)
		client.Close()
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
// Smart Queue for UDP
// ------------------------

const maxNewIPsConcurrencyUDP = 5
var newIPsSemaphoreUDP = make(chan struct{}, maxNewIPsConcurrencyUDP)

func acquireNewIPSlotUDP() {
	newIPsSemaphoreUDP <- struct{}{}
}

func releaseNewIPSlotUDP() {
	<-newIPsSemaphoreUDP
}

// ------------------------
// Three-Phase UDP Proxy Logic
// ------------------------
//
// 1) Minimal handshake + concurrency queue
// 2) Must get a response from the backend
// 3) Must see at least one more packet from the client within 3 seconds to confirm it’s not a single‐packet forgery.

type sessionDataUDP struct {
	clientAddr   *net.UDPAddr
	backendConn  *net.UDPConn
	lastActive   time.Time
	gotFollowUp  bool
	mu           sync.Mutex
	phase2Done   bool
	phase2Cancel chan struct{}
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

		// If trusted or whitelisted => forward immediately
		if isTrusted(clientIP) || isWhitelisted(clientIP) {
			forwardUDP(listenConn, backendAddr, clientAddr, buf[:n])
			continue
		}

		// If banned => ignore
		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			continue
		}
		bannedIPsMu.RUnlock()

		// If handshake not done => concurrency queue
		if !hasUDPCheckedHandshake(clientAddr.String()) {
			acquireNewIPSlotUDP()
			go func(data []byte, cAddr *net.UDPAddr) {
				defer releaseNewIPSlotUDP()
				handleNewUDP(listenConn, backendAddr, data, cAddr)
			}(buf[:n], clientAddr)
		} else {
			// If handshake was done but not whitelisted => ban
			if !isWhitelisted(clientIP) {
				log.Printf("[UDP] [%s] Already handshake-checked => banning.", clientAddr.String())
				banIP(clientIP)
				continue
			}
			// Otherwise forward
			forwardUDP(listenConn, backendAddr, clientAddr, buf[:n])
		}
	}
}

func handleNewUDP(listenConn *net.UDPConn, backendAddr *net.UDPAddr, data []byte, clientAddr *net.UDPAddr) {
	clientKey := clientAddr.String()
	clientIP := clientAddr.IP.String()

	// Check if banned or whitelisted
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		return
	}
	bannedIPsMu.RUnlock()

	if isWhitelisted(clientIP) {
		forwardUDP(listenConn, backendAddr, clientAddr, data)
		return
	}

	// Rate limiting
	udpPacketCountsMu.Lock()
	udpPacketCounts[clientKey]++
	if udpPacketCounts[clientKey] > udpThreshold {
		bannedIPsMu.Lock()
		bannedIPs[clientIP] = true
		bannedIPsMu.Unlock()
		udpPacketCountsMu.Unlock()
		log.Printf("[UDP] [%s] Banned: Excessive packet rate", clientKey)
		return
	}
	udpPacketCountsMu.Unlock()

	// Phase 1: minimal handshake
	if !disableUDPHandshakeCheck && !isFiveMHandshake(data) {
		udpHandshakeFailuresMu.Lock()
		udpHandshakeFailures[clientKey]++
		failCount := udpHandshakeFailures[clientKey]
		udpHandshakeFailuresMu.Unlock()
		log.Printf("[UDP] [%s] Invalid handshake attempt (%d/%d).", clientKey, failCount, udpHandshakeFailureLimit)
		if failCount >= udpHandshakeFailureLimit {
			banIP(clientIP)
		}
		return
	}

	// Phase 2: forward to backend, require at least 1 byte back
	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Printf("[UDP] [%s] Error dialing backend: %v", clientKey, err)
		return
	}
	_, werr := backendConn.Write(data)
	if werr != nil {
		log.Printf("[UDP] [%s] Error forwarding handshake to backend: %v", clientKey, werr)
		backendConn.Close()
		return
	}

	backendConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respBuf := make([]byte, 2048)
	rn, rerr := backendConn.Read(respBuf)
	backendConn.SetReadDeadline(time.Time{})
	if rerr != nil || rn < 1 {
		log.Printf("[UDP] [%s] No backend response => ban IP.", clientKey)
		banIP(clientIP)
		backendConn.Close()
		return
	}

	// Phase 3: require the client to send at least 1 more packet within 3 seconds
	// to confirm they're not a single-packet flooder.
	sd := &sessionDataUDP{
		clientAddr:   clientAddr,
		backendConn:  backendConn,
		lastActive:   time.Now(),
		gotFollowUp:  false,
		phase2Done:   true,
		phase2Cancel: make(chan struct{}),
	}

	updateWhitelist(clientIP) // We'll tentatively whitelist them
	markUDPCheckedHandshake(clientKey)
	log.Printf("[UDP] [%s] Authenticated => whitelisted (phase 2).", clientKey)

	// Send backend's response to the client
	_, _ = listenConn.WriteToUDP(respBuf[:rn], clientAddr)

	sessionMuUDP.Lock()
	sessionMapUDP[clientKey] = sd
	sessionMuUDP.Unlock()

	go handleUDPSession(listenConn, sd)

	// Wait up to 3s for another packet from the client
	select {
	case <-sd.phase2Cancel:
		// The client sent more data or we ended
	case <-time.After(3 * time.Second):
		sd.mu.Lock()
		if !sd.gotFollowUp {
			// They never sent more => ban them
			log.Printf("[UDP] [%s] No follow-up packet => banning IP (likely a single-packet forgery).", clientKey)
			banIP(clientIP)
		} else {
			log.Printf("[UDP] [%s] Follow-up seen => final whitelisting confirmed.", clientKey)
		}
		sd.mu.Unlock()
	}
}

func forwardUDP(listenConn *net.UDPConn, backendAddr *net.UDPAddr, clientAddr *net.UDPAddr, data []byte) {
	sessionMuUDP.Lock()
	key := clientAddr.String()
	sd, exists := sessionMapUDP[key]
	if !exists {
		// For already whitelisted IP
		backendConn, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			sessionMuUDP.Unlock()
			log.Printf("[UDP] Error dialing backend for client %s: %v", key, err)
			return
		}
		sd = &sessionDataUDP{
			clientAddr:   clientAddr,
			backendConn:  backendConn,
			lastActive:   time.Now(),
			phase2Cancel: make(chan struct{}),
		}
		sessionMapUDP[key] = sd
		sessionMuUDP.Unlock()
		go handleUDPSession(listenConn, sd)
	} else {
		sd.lastActive = time.Now()
		sessionMuUDP.Unlock()

		// If phase2 done but we haven't yet seen follow-up, mark it
		sd.mu.Lock()
		if sd.phase2Done && !sd.gotFollowUp {
			sd.gotFollowUp = true
			close(sd.phase2Cancel) // Let the 3s timer end
		}
		sd.mu.Unlock()
	}

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

	if *trustedIPsFlag != "" {
		ips := strings.Split(*trustedIPsFlag, ",")
		addTrustedIPs(ips)
	}

	log.Printf("[INFO] Starting proxy: forwarding to %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	go resetTCPCounts()
	go resetUDPPacketCounts()

	// Start TCP proxy (three-phase handshake + concurrency queue)
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

	// Start UDP proxy (three-phase handshake + concurrency queue)
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Start DDoS detection
	go monitorDDoS(*discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", *targetIP, *listenPort), *targetPort)

	select {}
}

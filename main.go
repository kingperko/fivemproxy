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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ------------------------
// Discord embed support
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
		return // no webhook configured
	}
	embed := discordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
	}
	payload := discordWebhookBody{
		Username: "Proxy DDOS Monitor",
		Embeds:   []discordEmbed{embed},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[DISCORD] Error marshaling embed JSON: %v", err)
		return
	}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[DISCORD] Error creating Discord request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DISCORD] Error sending to Discord: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("[DISCORD] Discord webhook returned status: %d", resp.StatusCode)
	}
}

// ------------------------
// Global variables & thresholds
// ------------------------

var (
	// Global counters for each interval.
	tcpConnCount   int64
	udpPacketCount int64

	// Per-IP event scores (cumulative across intervals).
	ipScores   = make(map[string]float64)
	ipScoresMu sync.Mutex

	// We'll also track per-interval raw counts.
	ipCounts   = make(map[string]int64)
	ipCountsMu sync.Mutex

	// Banned IPs.
	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	// Active TCP connections (IP as key).
	activeTCP   = make(map[string]bool)
	activeTCPMu sync.RWMutex

	// Attack mode flag.
	attackMode   bool
	attackModeMu sync.Mutex
)

// Interval duration.
const IntervalDuration = 10 * time.Second

// Thresholds (adjust as needed)
const (
	OverallThreshold = 150          // overall events in an interval to trigger attack mode (if >1 unique IP)
	ScoreThreshold   = 50.0         // cumulative score above which an IP is banned
	DecayFactor      = 0.8          // score decay factor per interval
	HandshakePenalty = 0.0          // handshake traffic doesn't add to score
	EventMultiplier  = 1.0          // each event adds this much to the score (can be tuned)
	RelativeThreshold = 0.8         // if one IP produces >80% of traffic in an interval, it's suspicious
)

// updateScore updates the cumulative score for an IP based on its current count.
func updateScore(ip string, count int64, average float64) {
	ipScoresMu.Lock()
	defer ipScoresMu.Unlock()

	// Only add to score if count is above twice the average.
	if float64(count) > average*2 {
		excess := float64(count) - average*2
		ipScores[ip] += excess * EventMultiplier
	} else {
		// Decay the score.
		ipScores[ip] *= DecayFactor
	}
}

// processInterval aggregates stats, updates scores, and takes action.
func processInterval(discordWebhook string) {
	// Capture and reset interval counters.
	tcp := atomic.SwapInt64(&tcpConnCount, 0)
	udp := atomic.SwapInt64(&udpPacketCount, 0)
	total := tcp + udp

	ipCountsMu.Lock()
	uniqueCount := len(ipCounts)
	// Compute average events per IP.
	var sum int64
	for _, cnt := range ipCounts {
		sum += cnt
	}
	avg := 0.0
	if uniqueCount > 0 {
		avg = float64(sum) / float64(uniqueCount)
	}
	// Build sorted list of IPs.
	type ipStat struct {
		IP    string
		Count int64
		Score float64
	}
	var statsList []ipStat
	for ip, cnt := range ipCounts {
		updateScore(ip, cnt, avg)
		ipScoresMu.Lock()
		score := ipScores[ip]
		ipScoresMu.Unlock()
		statsList = append(statsList, ipStat{IP: ip, Count: cnt, Score: score})
	}
	ipCounts = make(map[string]int64)
	ipCountsMu.Unlock()

	// Sort by score descending.
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].Score > statsList[j].Score
	})

	// Build textual bar graph for top 3 offenders.
	graphLines := ""
	maxScore := 1.0
	if len(statsList) > 0 {
		maxScore = statsList[0].Score
	}
	for i, s := range statsList {
		if i >= 3 {
			break
		}
		// Scale bar to 10 blocks.
		barLen := int((s.Score / maxScore) * 10)
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		graphLines += fmt.Sprintf("%s: %.2f (Count: %d) %s\n", s.IP, s.Score, s.Count, bar)
	}

	// Log the advanced summary.
	log.Printf("=== Interval Summary ===")
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", tcp, udp, total, uniqueCount)
	log.Printf("Top Offenders:\n%s", graphLines)

	// Advanced attack detection:
	attackModeMu.Lock()
	if uniqueCount > 1 && total > OverallThreshold {
		if !attackMode {
			attackMode = true
			desc := fmt.Sprintf("DDoS attack detected.\nTotal events: %d\nUnique IPs: %d\n\nTop Offenders:\n%s", total, uniqueCount, graphLines)
			log.Printf(">>> DDoS attack detected. Mitigation enabled.")
			sendDiscordEmbed(discordWebhook, "Server Mitigation Enabled", desc, 0xff6600)
		}
		// Ban any IP whose score exceeds ScoreThreshold or if it contributes more than RelativeThreshold of total.
		for _, s := range statsList {
			share := float64(s.Count) / float64(total)
			if s.Score > ScoreThreshold || share > RelativeThreshold {
				bannedIPsMu.Lock()
				bannedIPs[s.IP] = true
				bannedIPsMu.Unlock()
				log.Printf("BANNED: IP %s banned (Score: %.2f, Share: %.0f%%)", s.IP, s.Score, share*100)
			}
		}
	} else {
		if attackMode {
			attackMode = false
			desc := fmt.Sprintf("DDoS attack ended.\nTotal events: %d\nUnique IPs: %d\n\nTop Offenders:\n%s", total, uniqueCount, graphLines)
			log.Printf(">>> DDoS attack ended. %s", desc)
			sendDiscordEmbed(discordWebhook, "Attack Ended", desc, 0x00bfff)
		}
	}
	attackModeMu.Unlock()
}

// ------------------------
// TCP Proxy Section
// ------------------------

// isLegitHandshake checks if the initial data looks like a FiveM handshake.
func isLegitHandshake(data string) bool {
	lower := strings.ToLower(data)
	return strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client")
}

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientAddr := client.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]

	// If banned, drop connection.
	bannedIPsMu.RLock()
	if banned, exists := bannedIPs[clientIP]; exists && banned {
		bannedIPsMu.RUnlock()
		log.Printf("[TCP] Dropping connection from banned IP %s", clientIP)
		client.Close()
		return
	}
	bannedIPsMu.RUnlock()

	log.Printf("[TCP] Accepted connection from %s", clientAddr)
	activeTCPMu.Lock()
	activeTCP[clientIP] = true
	activeTCPMu.Unlock()
	defer func() {
		activeTCPMu.Lock()
		delete(activeTCP, clientIP)
		activeTCPMu.Unlock()
	}()

	// Read initial packet.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	initialData := ""
	legit := false
	if err == nil && n > 0 {
		initialData = string(buf[:n])
		legit = isLegitHandshake(initialData)
		if !legit {
			ipCountsMu.Lock()
			ipCounts[clientIP]++
			ipCountsMu.Unlock()
		}
		log.Printf("[TCP] Initial packet from %s: %q", clientAddr, initialData[:min(n, 64)])
		_, _ = client.Write([]byte{}) // echo nothing; just proceed
	} else if err != nil && err != io.EOF {
		log.Printf("[TCP] Error reading initial data from %s: %v", clientAddr, err)
		client.Close()
		return
	}

	atomic.AddInt64(&tcpConnCount, 1)
	if !legit {
		// Only count as an event if not a known handshake.
	} else {
		log.Printf("[TCP] Legitimate handshake detected from %s", clientAddr)
	}

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
		client.Close()
		return
	}
	defer backend.Close()

	// Forward initial data.
	if n > 0 {
		_, _ = backend.Write(buf[:n])
	}

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
	log.Printf("[TCP] Connection from %s closed after %v", clientAddr, time.Since(startTime))
}

func startTCPProxy(listenPort, targetIP, targetPort string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[TCP] Error starting TCP listener on port %s: %v", listenPort, err)
	}
	defer ln.Close()
	log.Printf("[TCP] Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP] Error accepting connection: %v", err)
			continue
		}
		go handleTCPConnection(conn, targetIP, targetPort)
	}
}

// ------------------------
// UDP Proxy Section (Naive NAT style)
// ------------------------

type udpEntry struct {
	backendConn *net.UDPConn
	lastSeen    time.Time
}

func startUDPProxy(listenPort, targetIP, targetPort string) {
	addr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[UDP] Error resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[UDP] Error listening on UDP port %s: %v", listenPort, err)
	}
	defer conn.Close()
	log.Printf("[UDP] Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

	backendMap := make(map[string]*udpEntry)
	var mu sync.Mutex
	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP] Error reading: %v", err)
			continue
		}
		clientKey := clientAddr.String()
		clientIP := strings.Split(clientKey, ":")[0]

		// Check for legitimate UDP handshake (if payload is ASCII and contains known endpoints).
		payloadStr := strings.ToLower(string(buf[:n]))
		legit := strings.Contains(payloadStr, "get /info.json") || strings.Contains(payloadStr, "get /players.json")

		uniqueIPsMu.Lock()
		ipCounts[clientIP]++ // count every packet
		uniqueIPsMu.Unlock()

		// Only update DDoS score if not a legitimate handshake.
		if !legit {
			// update per-IP event count (for UDP) is already done above
		} else {
			log.Printf("[UDP] Legitimate handshake UDP from %s", clientIP)
		}

		bannedIPsMu.RLock()
		if banned, exists := bannedIPs[clientIP]; exists && banned {
			bannedIPsMu.RUnlock()
			log.Printf("[UDP] Dropping packet from banned IP %s", clientIP)
			continue
		}
		bannedIPsMu.RUnlock()

		atomic.AddInt64(&udpPacketCount, 1)
		mu.Lock()
		entry, found := backendMap[clientKey]
		if !found {
			targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
			if err != nil {
				log.Printf("[UDP] Error resolving backend address: %v", err)
				mu.Unlock()
				continue
			}
			bc, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				log.Printf("[UDP] Error dialing backend for %s: %v", clientKey, err)
				mu.Unlock()
				continue
			}
			entry = &udpEntry{
				backendConn: bc,
				lastSeen:    time.Now(),
			}
			backendMap[clientKey] = entry
			go func(client *net.UDPAddr, backendConn *net.UDPConn, key string) {
				bBuf := make([]byte, 2048)
				for {
					backendConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
					n2, _, err2 := backendConn.ReadFromUDP(bBuf)
					if err2 != nil {
						log.Printf("[UDP] Closing connection for %s: %v", key, err2)
						backendConn.Close()
						mu.Lock()
						delete(backendMap, key)
						mu.Unlock()
						return
					}
					conn.WriteToUDP(bBuf[:n2], client)
				}
			}(clientAddr, entry.backendConn, clientKey)
		}
		entry.lastSeen = time.Now()
		_, _ = entry.backendConn.Write(buf[:n])
		mu.Unlock()
	}
}

// ------------------------
// Main function
// ------------------------

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL for DDoS alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	// Start advanced interval processing every IntervalDuration.
	go func() {
		ticker := time.NewTicker(IntervalDuration)
		defer ticker.Stop()
		for range ticker.C {
			processInterval(*discordWebhook)
		}
	}()

	go startTCPProxy(*listenPort, *targetIP, *targetPort)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

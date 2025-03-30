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
// Global variables and thresholds
// ------------------------

var (
	// Global interval counters.
	tcpConnCount   int64
	udpPacketCount int64

	// Per-interval raw event counts per IP.
	ipCounts   = make(map[string]int64)
	ipCountsMu sync.Mutex

	// Cumulative suspicion scores per IP.
	ipScores   = make(map[string]float64)
	ipScoresMu sync.Mutex

	// Banned IPs.
	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	// Active TCP connections.
	activeTCP   = make(map[string]bool)
	activeTCPMu sync.RWMutex

	// Attack mode flag.
	attackMode   bool
	attackModeMu sync.Mutex
)

// Interval duration.
const IntervalDuration = 10 * time.Second

// Detection thresholds (adjust as needed)
const (
	OverallThreshold  int64   = 150   // Overall events to trigger attack mode (if >1 unique IP)
	ScoreThreshold    float64 = 50.0  // If an IP's cumulative score exceeds this, ban it.
	DecayFactor       float64 = 0.8   // Each interval, scores decay by this factor.
	EventMultiplier   float64 = 1.0   // Each event adds this many points.
	RelativeThreshold float64 = 0.8   // If one IP produces >80% of total events, it's suspect.
)

// updateRawCount increases the raw count for an IP.
func updateRawCount(ip string) {
	ipCountsMu.Lock()
	ipCounts[ip]++
	ipCountsMu.Unlock()
}

// updateScore updates the cumulative score for an IP.
func updateScore(ip string, count int64, avg float64) {
	ipScoresMu.Lock()
	defer ipScoresMu.Unlock()
	if float64(count) > avg*2 {
		excess := float64(count) - avg*2
		ipScores[ip] += excess * EventMultiplier
	} else {
		ipScores[ip] *= DecayFactor
	}
	// If the IP has an active TCP connection, be more lenient.
	activeTCPMu.RLock()
	_, active := activeTCP[ip]
	activeTCPMu.RUnlock()
	if active && ipScores[ip] < ScoreThreshold/2 {
		ipScores[ip] = 0
	}
}

// ------------------------
// Interval Processing
// ------------------------

func processInterval(discordWebhook string) {
	// Capture and reset interval stats.
	ipCountsMu.Lock()
	intervalCounts := make(map[string]int64)
	for k, v := range ipCounts {
		intervalCounts[k] = v
	}
	ipCounts = make(map[string]int64)
	ipCountsMu.Unlock()

	tcp := atomic.SwapInt64(&tcpConnCount, 0)
	udp := atomic.SwapInt64(&udpPacketCount, 0)
	total := tcp + udp
	uniqueCount := len(intervalCounts)

	// Calculate average events per IP.
	avg := 0.0
	if uniqueCount > 0 {
		var sum int64
		for _, cnt := range intervalCounts {
			sum += cnt
		}
		avg = float64(sum) / float64(uniqueCount)
	}

	// Update cumulative scores.
	for ip, cnt := range intervalCounts {
		updateScore(ip, cnt, avg)
	}

	// Build sorted list of IPs by score.
	type ipStat struct {
		IP    string
		Count int64
		Score float64
	}
	var statsList []ipStat
	ipScoresMu.Lock()
	for ip, score := range ipScores {
		count := intervalCounts[ip]
		statsList = append(statsList, ipStat{IP: ip, Count: count, Score: score})
	}
	ipScoresMu.Unlock()
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].Score > statsList[j].Score
	})

	// Build a textual bar graph for top offenders.
	graphLines := ""
	maxScore := 1.0
	if len(statsList) > 0 {
		maxScore = statsList[0].Score
	}
	for i, s := range statsList {
		if i >= 3 {
			break
		}
		barLen := int((s.Score / maxScore) * 10)
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		graphLines += fmt.Sprintf("%s: %.2f (Count: %d) %s\n", s.IP, s.Score, s.Count, bar)
	}

	// Log interval summary.
	log.Printf("=== Interval Summary ===")
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", tcp, udp, total, uniqueCount)
	log.Printf("Top Offenders:\n%s", graphLines)

	// Advanced attack detection.
	attackModeMu.Lock()
	if uniqueCount > 1 && total > OverallThreshold {
		if !attackMode {
			attackMode = true
			desc := fmt.Sprintf("DDoS attack detected.\nTotal events: %d\nUnique IPs: %d\n\nTop Offenders:\n%s", total, uniqueCount, graphLines)
			log.Printf(">>> DDoS attack detected. Mitigation enabled.")
			sendDiscordEmbed(discordWebhook, "Server Mitigation Enabled", desc, 0xff6600)
		}
		// Ban any IP with high relative share or cumulative score.
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

	// Check initial handshake.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	legit := false
	if err == nil && n > 0 {
		data := string(buf[:n])
		legit = isLegitHandshake(data)
		if !legit {
			ipCountsMu.Lock()
			ipCounts[clientIP]++
			ipCountsMu.Unlock()
		} else {
			log.Printf("[TCP] Legitimate handshake from %s", clientAddr)
		}
		log.Printf("[TCP] Initial packet from %s: %q", clientAddr, data[:min(n, 64)])
		// Forward initial data.
	} else if err != nil && err != io.EOF {
		log.Printf("[TCP] Error reading from %s: %v", clientAddr, err)
		client.Close()
		return
	}

	atomic.AddInt64(&tcpConnCount, 1)

	// Always increment cumulative event for TCP.
	// (Legitimate handshake traffic is not heavily penalized.)
	ipCountsMu.Lock()
	ipCounts[clientIP]++
	ipCountsMu.Unlock()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
		client.Close()
		return
	}
	defer backend.Close()

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

		// Check if payload looks like a handshake.
		payloadStr := strings.ToLower(string(buf[:n]))
		legit := strings.Contains(payloadStr, "get /info.json") || strings.Contains(payloadStr, "get /players.json")
		if !legit {
			ipCountsMu.Lock()
			ipCounts[clientIP]++
			ipCountsMu.Unlock()
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

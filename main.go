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
// Proxy & DDoS detection globals
// ------------------------

var (
	// Global counters for TCP and UDP events (per interval)
	tcpConnCount   int64
	udpPacketCount int64

	// ipEventCounts collects per-IP event counts during the interval.
	ipEventCounts   = make(map[string]int64)
	ipEventCountsMu sync.Mutex

	// bannedIPs: IPs that have been banned.
	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	// activeTCP tracks IPs with active TCP connections.
	activeTCP   = make(map[string]bool)
	activeTCPMu sync.RWMutex

	// Overall attack mode flag.
	attackMode      bool
	attackModeMu    sync.Mutex
	lastInterval    IntervalStats
)

// IntervalStats aggregates stats over a fixed interval.
type IntervalStats struct {
	TotalTCP  int64
	TotalUDP  int64
	IPCounts  map[string]int64
	StartTime time.Time
}

// We'll use a sliding window interval.
const IntervalDuration = 10 * time.Second

// Detection thresholds.
const (
	OverallThreshold  int64   = 150  // overall events in an interval to trigger attack mode (if >1 unique IP)
	BaselineFactor    float64 = 2.0  // only add score if an IP's events exceed (average * BaselineFactor)
	ScoreThreshold    float64 = 50.0 // cumulative score above which the IP is banned
	DecayFactor       float64 = 0.8  // score decays each interval by this factor
	RelativeThreshold float64 = 0.8  // if one IP exceeds 80% of total events, it's suspect
)

// ipScores stores a cumulative score for each IP.
var (
	ipScores   = make(map[string]float64)
	ipScoresMu sync.Mutex
)

// updateIntervalStats aggregates current interval stats.
func updateIntervalStats() IntervalStats {
	ipEventCountsMu.Lock()
	defer ipEventCountsMu.Unlock()
	return IntervalStats{
		TotalTCP:  atomic.LoadInt64(&tcpConnCount),
		TotalUDP:  atomic.LoadInt64(&udpPacketCount),
		IPCounts:  copyMap(ipEventCounts),
		StartTime: time.Now(),
	}
}

// copyMap returns a shallow copy of a map.
func copyMap(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// resetInterval resets the global per-interval counters.
func resetIntervalStats() {
	atomic.StoreInt64(&tcpConnCount, 0)
	atomic.StoreInt64(&udpPacketCount, 0)
	ipEventCountsMu.Lock()
	ipEventCounts = make(map[string]int64)
	ipEventCountsMu.Unlock()
}

// processInterval analyzes stats and updates ipScores; bans IPs if their score exceeds threshold.
func processInterval(discordWebhook string) {
	stats := updateIntervalStats()
	total := stats.TotalTCP + stats.TotalUDP
	uniqueCount := len(stats.IPCounts)

	// Calculate baseline average per IP.
	var avg float64
	if uniqueCount > 0 {
		avg = float64(total) / float64(uniqueCount)
	}

	// Update ipScores for each IP.
	ipScoresMu.Lock()
	for ip, count := range stats.IPCounts {
		// If the count exceeds (avg * BaselineFactor), add the excess to the score.
		if float64(count) > avg*BaselineFactor {
			excess := float64(count) - avg*BaselineFactor
			ipScores[ip] += excess
		} else {
			// Otherwise, decay the score.
			ipScores[ip] *= DecayFactor
		}
		// If an IP has an active TCP connection, we can be more lenient:
		activeTCPMu.RLock()
		_, active := activeTCP[ip]
		activeTCPMu.RUnlock()
		if active && ipScores[ip] < ScoreThreshold/2 {
			ipScores[ip] = 0 // reset score for active connections
		}
		// Ban IP if score exceeds threshold.
		if ipScores[ip] > ScoreThreshold {
			bannedIPsMu.Lock()
			bannedIPs[ip] = true
			bannedIPsMu.Unlock()
			log.Printf("BANNED: IP %s banned with score %.2f", ip, ipScores[ip])
		}
	}
	// Build a sorted list of offenders.
	type ipScore struct {
		IP    string
		Score float64
		Count int64
	}
	var offenders []ipScore
	for ip, count := range stats.IPCounts {
		score := ipScores[ip]
		offenders = append(offenders, ipScore{IP: ip, Score: score, Count: count})
	}
	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].Score > offenders[j].Score
	})
	ipScoresMu.Unlock()

	// Build a textual bar graph for top 3 offenders.
	graphLines := ""
	maxScore := 1.0
	if len(offenders) > 0 {
		maxScore = offenders[0].Score
	}
	for i, o := range offenders {
		if i >= 3 {
			break
		}
		// Scale the bar to 10 blocks.
		barLen := int((o.Score / maxScore) * 10)
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		graphLines += fmt.Sprintf("%s: %.2f (Count: %d) %s\n", o.IP, o.Score, o.Count, bar)
	}

	// Log summary.
	log.Printf("=== Advanced Interval Summary ===")
	log.Printf("Interval Duration: %v", IntervalDuration)
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", stats.TotalTCP, stats.TotalUDP, total, uniqueCount)
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
	} else {
		if attackMode {
			attackMode = false
			desc := fmt.Sprintf("DDoS attack ended.\nTotal events: %d\nUnique IPs: %d\n\nTop Offenders:\n%s", total, uniqueCount, graphLines)
			log.Printf(">>> DDoS attack ended. %s", desc)
			sendDiscordEmbed(discordWebhook, "Attack Ended", desc, 0x00bfff)
		}
	}
	attackModeMu.Unlock()

	resetIntervalStats()
}

// ------------------------
// TCP Proxy Section
// ------------------------

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

	atomic.AddInt64(&tcpConnCount, 1)
	ipEventCountsMu.Lock()
	ipEventCounts[clientIP]++
	ipEventCountsMu.Unlock()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
		client.Close()
		return
	}
	defer backend.Close()

	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	if err == nil && n > 0 {
		initialData := string(buf[:n])
		log.Printf("[TCP] Initial packet from %s: %q", clientAddr, initialData[:min(n, 64)])
		_, _ = backend.Write(buf[:n])
	} else if err != nil && err != io.EOF {
		log.Printf("[TCP] Error reading initial data from %s: %v", clientAddr, err)
		return
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

var (
	ipEventCountsMu sync.Mutex // protects ipEventCounts map
)

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
		uniqueIPs.Store(clientIP, true)
		// Only count UDP events if no active TCP exists.
		activeTCPMu.RLock()
		_, active := activeTCP[clientIP]
		activeTCPMu.RUnlock()
		if !active {
			ipEventCountsMu.Lock()
			ipEventCounts[clientIP]++
			ipEventCountsMu.Unlock()
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

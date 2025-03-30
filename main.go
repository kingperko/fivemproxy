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
// Constants for advanced DDoS detection
// ------------------------

const (
	IntervalDuration   = 10 * time.Second
	OverallThreshold   int64 = 150  // overall events in an interval to trigger attack mode (if >1 unique IP)
	SingleIPThreshold  int64 = 400  // threshold for single-client scenario
	RelativeThreshold        = 0.8  // if an IP produces >80% of events in multi-IP scenario, it's suspicious
	DiscordGraphFactor int64 = 10   // divisor to scale the bar graph (adjust as needed)
)

// ------------------------
// Data structures for interval stats
// ------------------------

type IntervalStats struct {
	TotalTCP  int64
	TotalUDP  int64
	IPCounts  map[string]int64
	StartTime time.Time
}

var (
	statsMutex   sync.Mutex
	currentStats = IntervalStats{IPCounts: make(map[string]int64), StartTime: time.Now()}
)

// updateStats updates the current stats for a given IP and protocol.
func updateStats(ip string, protocol string) {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	if protocol == "tcp" {
		currentStats.TotalTCP++
	} else if protocol == "udp" {
		currentStats.TotalUDP++
	}
	currentStats.IPCounts[ip]++
}

// resetStats resets the interval stats and returns the previous stats.
func resetStats() IntervalStats {
	statsMutex.Lock()
	defer statsMutex.Unlock()
	prev := currentStats
	currentStats = IntervalStats{IPCounts: make(map[string]int64), StartTime: time.Now()}
	return prev
}

// generateBar returns a simple text bar for a given value.
func generateBar(value int64, max int64) string {
	// Scale to a maximum of 10 blocks.
	blocks := int((float64(value) / float64(max)) * 10)
	if blocks < 1 {
		blocks = 1
	}
	return strings.Repeat("█", blocks)
}

// ------------------------
// Global variables for active TCP tracking and banning
// ------------------------

var (
	activeTCP sync.Map // map[string]bool for IPs with active TCP connections
	bannedIPs sync.Map // map[string]bool for banned IPs
)

// For overall attack mode.
var (
	attackMode      bool
	attackModeLock  sync.Mutex
	lastAttackStats IntervalStats
)

// For per-IP event counting.
var (
	ipEventCounts sync.Map // map[string]*int64
)

// incrementIPEvent increments the counter for a given IP.
func incrementIPEvent(ip string) {
	v, _ := ipEventCounts.LoadOrStore(ip, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

// ------------------------
// Advanced interval processing and DDoS screening
// ------------------------

func processIntervalStats(discordWebhook string) {
	stats := resetStats()
	total := stats.TotalTCP + stats.TotalUDP
	uniqueCount := len(stats.IPCounts)

	// Build sorted list of IPs.
	type ipStat struct {
		IP    string
		Count int64
	}
	var statsList []ipStat
	for ip, count := range stats.IPCounts {
		statsList = append(statsList, ipStat{IP: ip, Count: count})
	}
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].Count > statsList[j].Count
	})

	// Build a simple textual bar graph for top 3 offenders.
	graphLines := ""
	maxCount := int64(1)
	if len(statsList) > 0 {
		maxCount = statsList[0].Count
	}
	for i, s := range statsList {
		if i >= 3 {
			break
		}
		bar := generateBar(s.Count, maxCount/DiscordGraphFactor+1)
		graphLines += fmt.Sprintf("%s: %d events %s\n", s.IP, s.Count, bar)
	}

	// Log advanced interval summary.
	log.Printf("=== Advanced Interval Summary ===")
	log.Printf("Duration: %v", IntervalDuration)
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", stats.TotalTCP, stats.TotalUDP, total, uniqueCount)
	log.Printf("Top Offenders:\n%s", graphLines)

	// Advanced screening.
	var banned []string
	if uniqueCount > 1 && total > OverallThreshold {
		// If one IP produces more than 80% of the traffic, ban it.
		for _, s := range statsList {
			share := float64(s.Count) / float64(total)
			if share > RelativeThreshold {
				bannedIPs.Store(s.IP, true)
				banned = append(banned, fmt.Sprintf("%s (%.0f%%)", s.IP, share*100))
				log.Printf("BANNED: IP %s banned for excessive share (%.0f%%)", s.IP, share*100)
			}
		}
		if !attackMode {
			attackMode = true
			lastAttackStats = stats
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
}

// ------------------------
// TCP Proxy Section
// ------------------------

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientAddr := client.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]

	// Drop connection if banned.
	if _, banned := bannedIPs.Load(clientIP); banned {
		log.Printf("[TCP] Dropping connection from banned IP %s", clientIP)
		client.Close()
		return
	}

	log.Printf("[TCP] Accepted connection from %s", clientAddr)
	// Mark IP as active on TCP.
	activeTCP.Store(clientIP, true)
	defer activeTCP.Delete(clientIP)

	updateStats(clientIP, "tcp")
	incrementIPEvent(clientIP)

	defer client.Close()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
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
		// Only count UDP events if no active TCP from this IP.
		if _, active := activeTCP.Load(clientIP); !active {
			updateStats(clientIP, "udp")
			incrementIPEvent(clientIP)
		}

		// Drop packet if IP is banned.
		if _, banned := bannedIPs.Load(clientIP); banned {
			log.Printf("[UDP] Dropping packet from banned IP %s", clientIP)
			continue
		}

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

	// Start advanced interval processing.
	go func() {
		ticker := time.NewTicker(IntervalDuration)
		defer ticker.Stop()
		for range ticker.C {
			processIntervalStats(*discordWebhook)
		}
	}()

	go startTCPProxy(*listenPort, *targetIP, *targetPort)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

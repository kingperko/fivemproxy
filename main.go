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
// Data structures for advanced DDoS detection
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
	activeTCP sync.Map // map[string]bool of IPs with active TCP connections
	bannedIPs sync.Map // map[string]bool of banned IPs
)

// For our new system, we do not automatically ban an IP on a single interval.
var (
	attackMode      bool
	attackModeLock  sync.Mutex
	lastAttackStats IntervalStats
)

// Configuration thresholds (adjust as needed)
const (
	IntervalDuration   = 10 * time.Second
	OverallThreshold   = 150  // overall events in an interval to trigger attack mode (if >1 unique IP)
	SingleIPThreshold  = 400  // if only one unique IP, it must exceed this to be flagged (to avoid banning legitimate solo players)
	RelativeThreshold  = 0.8  // if an IP produces >80% of events in multi-IP scenario, it’s suspicious
	DiscordGraphFactor = 10   // divisor to scale the bar graph (adjust for your traffic)
)

// processStats analyzes the stats from the interval and performs advanced DDoS screening.
func processStats(discordWebhook string) {
	stats := resetStats()
	total := stats.TotalTCP + stats.TotalUDP
	uniqueCount := len(stats.IPCounts)

	// Build list of offenders.
	type ipStat struct {
		IP    string
		Count int64
	}
	var offenders []ipStat
	for ip, count := range stats.IPCounts {
		offenders = append(offenders, ipStat{IP: ip, Count: count})
	}
	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].Count > offenders[j].Count
	})

	// Log advanced interval summary.
	log.Printf("=== Interval Summary ===")
	log.Printf("Interval Duration: %v", IntervalDuration)
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", stats.TotalTCP, stats.TotalUDP, total, uniqueCount)
	log.Printf("Top Offenders:")
	maxCount := int64(1)
	if len(offenders) > 0 {
		maxCount = offenders[0].Count
	}
	for i, off := range offenders {
		if i >= 3 {
			break
		}
		bar := generateBar(off.Count, maxCount/DiscordGraphFactor+1)
		log.Printf("  %s : %d events %s", off.IP, off.Count, bar)
	}

	// Advanced screening: if there is more than one unique IP, use relative thresholds.
	var banned []string
	if uniqueCount > 1 && total > OverallThreshold {
		// For each IP, if its share exceeds RelativeThreshold, mark it.
		for _, off := range offenders {
			share := float64(off.Count) / float64(total)
			if share > RelativeThreshold {
				bannedIPs.Store(off.IP, true)
				banned = append(banned, fmt.Sprintf("%s (%.0f%%)", off.IP, share*100))
				log.Printf("BANNED: IP %s banned (share: %.0f%%)", off.IP, share*100)
			}
		}
	} else if uniqueCount == 1 {
		// Single IP scenario.
		for _, off := range offenders {
			if off.Count > SingleIPThreshold {
				bannedIPs.Store(off.IP, true)
				banned = append(banned, fmt.Sprintf("%s (count: %d)", off.IP, off.Count))
				log.Printf("BANNED: IP %s banned (single client, count: %d)", off.IP, off.Count)
			}
		}
	}

	// Attack mode detection: if overall total is high, trigger attack mode.
	attackModeLock.Lock()
	if uniqueCount > 1 && total > OverallThreshold {
		if !attackMode {
			attackMode = true
			lastAttackStats = stats
			// Send attack start embed with advanced data.
			desc := fmt.Sprintf("DDoS attack detected.\nTotal events: %d\nUnique IPs: %d", total, uniqueCount)
			// Append top offender info.
			if len(offenders) > 0 {
				desc += "\nTop Offender: " + offenders[0].IP + fmt.Sprintf(" (%d events)", offenders[0].Count)
			}
			// Add a simple bar graph for top 3 offenders.
			for i, off := range offenders {
				if i >= 3 {
					break
				}
				bar := generateBar(off.Count, maxCount/DiscordGraphFactor+1)
				desc += fmt.Sprintf("\n%s : %d events %s", off.IP, off.Count, bar)
			}
			log.Printf(">>> DDOS attack detected. Mitigation enabled.")
			sendDiscordEmbed(discordWebhook, "Server Mitigation Enabled", desc, 0xff6600)
		}
	} else {
		if attackMode {
			// If traffic drops below threshold for two consecutive intervals, consider attack over.
			// (For simplicity, we don't count consecutive safe intervals here, but you could add that.)
			attackMode = false
			desc := fmt.Sprintf("DDoS attack ended.\nPeak events: %d\nUnique IPs: %d", total, uniqueCount)
			// Add top offenders.
			for i, off := range offenders {
				if i >= 3 {
					break
				}
				bar := generateBar(off.Count, maxCount/DiscordGraphFactor+1)
				desc += fmt.Sprintf("\n%s : %d events %s", off.IP, off.Count, bar)
			}
			log.Printf(">>> DDOS attack ended. %s", desc)
			sendDiscordEmbed(discordWebhook, "Attack Ended", desc, 0x00bfff)
		}
	}
	attackModeLock.Unlock()
}

// ------------------------
// TCP Proxy Section
// ------------------------

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientAddr := client.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]

	// If banned, drop connection.
	if _, banned := bannedIPs.Load(clientIP); banned {
		log.Printf("[TCP] Dropping connection from banned IP %s", clientIP)
		client.Close()
		return
	}

	log.Printf("[TCP] Accepted connection from %s", clientAddr)
	// Mark as active.
	activeTCP.Store(clientIP, true)
	defer activeTCP.Delete(clientIP)

	// Update stats.
	updateStats(clientIP, "tcp")

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
		// Update stats: only count UDP events if no active TCP exists.
		if _, active := activeTCP.Load(clientIP); !active {
			updateStats(clientIP, "udp")
		}
		// Drop packet if banned.
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

	// Start advanced monitoring every IntervalDuration.
	go func() {
		ticker := time.NewTicker(IntervalDuration)
		defer ticker.Stop()
		for range ticker.C {
			processIntervalStats(*discordWebhook)
		}
	}()

	// Start proxies.
	go startTCPProxy(*listenPort, *targetIP, *targetPort)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

// processIntervalStats analyzes and resets current interval stats.
func processIntervalStats(discordWebhook string) {
	statsMutex.Lock()
	totalTCP := currentStats.TotalTCP
	totalUDP := currentStats.TotalUDP
	ipCounts := currentStats.IPCounts
	statsMutex.Unlock()

	total := totalTCP + totalUDP
	uniqueCount := len(ipCounts)

	// Build sorted list of IPs.
	type ipStat struct {
		IP    string
		Count int64
	}
	var statsList []ipStat
	for ip, count := range ipCounts {
		statsList = append(statsList, ipStat{IP: ip, Count: count})
	}
	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].Count > statsList[j].Count
	})

	// Build a textual bar graph for top 3 offenders.
	graphLines := ""
	maxCount := int64(1)
	if len(statsList) > 0 {
		maxCount = statsList[0].Count
	}
	for i, s := range statsList {
		if i >= 3 {
			break
		}
		bar := strings.Repeat("█", int((float64(s.Count)/float64(maxCount))*10))
		graphLines += fmt.Sprintf("%s: %d events %s\n", s.IP, s.Count, bar)
	}

	// Log summary.
	log.Printf("=== Advanced Interval Summary ===")
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", totalTCP, totalUDP, total, uniqueCount)
	log.Printf("Top Offenders:\n%s", graphLines)

	// Advanced screening and ban decisions.
	// For example, if total > OverallThreshold and one IP exceeds 80% of traffic, ban it.
	attackModeLock.Lock()
	if uniqueCount > 1 && total > thresholdEvents {
		for _, s := range statsList {
			share := float64(s.Count) / float64(total)
			if share > 0.8 { // more than 80% of traffic
				bannedIPs.Store(s.IP, true)
				log.Printf("BANNED: IP %s banned for excessive share (%.0f%%)", s.IP, share*100)
			}
		}
		if !attackMode {
			attackMode = true
			lastAttackStats = currentStats
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
	attackModeLock.Unlock()

	// Reset the stats for the next interval.
	statsMutex.Lock()
	currentStats = IntervalStats{IPCounts: make(map[string]int64), StartTime: time.Now()}
	statsMutex.Unlock()
}

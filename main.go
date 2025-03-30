// If you understand and want to proceed, repeat the command including --classic.
// For example, if installing Go via snap:
//     sudo snap install go --classic
// Then run your program with:
//     go run aloswall.go -targetIP=<BACKEND_IP> -targetPort=<BACKEND_PORT> -listenPort=<PROXY_PORT> -discordWebhook=<WEBHOOK_URL>

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

// ------------------------
// Utility Functions
// ------------------------

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// btom converts bytes to megabytes.
func btom(bytes int64) float64 {
	const bytesInMegabyte = 1024 * 1024
	return float64(bytes) / float64(bytesInMegabyte)
}

// ------------------------
// Discord Embed Support
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
		Username: "Smart DDOS Protection - YourBrand",
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
// Global Variables & Constants
// ------------------------

// Proxy & DDoS detection globals (for overall interval stats)
var (
	tcpConnCount   int64
	udpPacketCount int64

	// ipEventCounts collects per-IP event counts (used in overall detection)
	ipEventCounts   = make(map[string]int64)
	ipEventCountsMu sync.Mutex

	// bannedIPs: IPs that are banned (by smart protection or overall score)
	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	// activeTCP tracks IPs with active TCP connections.
	activeTCP   = make(map[string]bool)
	activeTCPMu sync.RWMutex

	// For UDP proxy unique IP storage.
	uniqueIPs sync.Map

	// Overall attack mode flag.
	attackMode   bool
	attackModeMu sync.Mutex
)

// IntervalStats aggregates stats over a fixed interval.
type IntervalStats struct {
	TotalTCP  int64
	TotalUDP  int64
	IPCounts  map[string]int64
	StartTime time.Time
}

const IntervalDuration = 10 * time.Second

// Detection thresholds for overall scoring.
const (
	OverallThreshold  int64   = 150
	BaselineFactor    float64 = 2.0
	ScoreThreshold    float64 = 50.0
	DecayFactor       float64 = 0.8
	RelativeThreshold float64 = 0.8
)

var (
	ipScores   = make(map[string]float64)
	ipScoresMu sync.Mutex
)

func copyMap(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

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

func resetIntervalStats() {
	atomic.StoreInt64(&tcpConnCount, 0)
	atomic.StoreInt64(&udpPacketCount, 0)
	ipEventCountsMu.Lock()
	ipEventCounts = make(map[string]int64)
	ipEventCountsMu.Unlock()
}

// processInterval analyzes overall stats, updates scores, and sends Discord notifications.
func processInterval(discordWebhook string) {
	stats := updateIntervalStats()
	total := stats.TotalTCP + stats.TotalUDP
	uniqueCount := len(stats.IPCounts)

	var avg float64
	if uniqueCount > 0 {
		avg = float64(total) / float64(uniqueCount)
	}

	ipScoresMu.Lock()
	for ip, count := range stats.IPCounts {
		if float64(count) > avg*BaselineFactor {
			excess := float64(count) - avg*BaselineFactor
			ipScores[ip] += excess
		} else {
			ipScores[ip] *= DecayFactor
		}
		activeTCPMu.RLock()
		_, active := activeTCP[ip]
		activeTCPMu.RUnlock()
		if active && ipScores[ip] < ScoreThreshold/2 {
			ipScores[ip] = 0
		}
		if ipScores[ip] > ScoreThreshold {
			bannedIPsMu.Lock()
			bannedIPs[ip] = true
			bannedIPsMu.Unlock()
			log.Printf("BANNED: IP %s banned with score %.2f", ip, ipScores[ip])
		}
	}
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

	graphLines := ""
	maxScore := 1.0
	if len(offenders) > 0 {
		maxScore = offenders[0].Score
	}
	for i, o := range offenders {
		if i >= 3 {
			break
		}
		barLen := int((o.Score / maxScore) * 10)
		if barLen < 1 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)
		graphLines += fmt.Sprintf("%s: %.2f (Count: %d) %s\n", o.IP, o.Score, o.Count, bar)
	}

	log.Printf("=== Interval Summary ===")
	log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", stats.TotalTCP, stats.TotalUDP, total, uniqueCount)
	log.Printf("Top Offenders:\n%s", graphLines)

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
			log.Printf(">>> DDoS attack ended.")
			sendDiscordEmbed(discordWebhook, "Attack Ended", desc, 0x00bfff)
		}
	}
	attackModeMu.Unlock()
	resetIntervalStats()
}

// ------------------------
// Advanced Per-IP Smart Protection Store
// ------------------------

// Ipin holds per-IP data for smart protection.
type Ipin struct {
	PPS         int64
	Data        int64
	SYN         int64
	Mac1        string
	Mac2        string
	Mac3        string
	Blocked     bool
	Delete      bool
	Lastblocked time.Time
	Lastseen    time.Time
	FirstSeen   time.Time
	OffenseCount int
}

// IPData wraps Ipin with a mutex.
type IPData struct {
	Data *Ipin
	Lock sync.Mutex
}

// IPStore tracks all IPData.
type IPStore struct {
	ips map[string]*IPData
	sync.Mutex
}

var store = NewIPStore()

func NewIPStore() *IPStore {
	return &IPStore{
		ips: make(map[string]*IPData),
	}
}

func (s *IPStore) GetOrCreateIPData(ip string) *IPData {
	s.Lock()
	defer s.Unlock()
	ipData, exists := s.ips[ip]
	if !exists {
		ipData = &IPData{Data: &Ipin{FirstSeen: time.Now()}}
		s.ips[ip] = ipData
	}
	return ipData
}

func (s *IPStore) IterateOverIPs(operation func(ip string, data *Ipin)) {
	s.Lock()
	defer s.Unlock()
	for ip, ipData := range s.ips {
		ipData.Lock.Lock()
		operation(ip, ipData.Data)
		if ipData.Data.Delete {
			delete(s.ips, ip)
		}
		ipData.Lock.Unlock()
	}
}

// getRegion returns a simple region based on IP (stub).
func getRegion(ip string) string {
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.16.") {
		return "Private"
	}
	if strings.HasPrefix(ip, "8.") {
		return "US"
	}
	if strings.HasPrefix(ip, "1.") {
		return "EU"
	}
	return "Global"
}

// Smart protection constants.
const (
	gracePeriod = 10 * time.Second
	maxOffense  = 2
	// Thresholds (from pterodactyl config sample)
	TCPDataThresholdMB = 9
	UDPDataThresholdMB = 9
	PPStcpLow          = 3000
	PPStcpHigh         = 850
	PPSudpLow          = 4000
	PPSudpHigh         = 1000
	AllowedSyn         = 5
)

// banIP permanently bans an IP.
func banIP(ip string) {
	err := addIPToIPSet("banlist_perm", ip)
	if err != nil {
		log.Printf("Failed to add %s to banlist_perm: %v", ip, err)
	} else {
		log.Printf("IP %s added to permanent ban list.", ip)
	}
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// Dummy ipset functions (assume ipset is available on system).
func ensureIPSet(setName string) error {
	cmd := exec.Command("ipset", "list", setName)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Ipset '%s' does not exist. Creating it...\n", setName)
		cmd = exec.Command("ipset", "create", setName, "hash:ip")
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("failed to create ipset '%s': %w", setName, err)
		}
	}
	return nil
}

func addIPToIPSet(name, ip string) error {
	cmd := exec.Command("ipset", "add", name, ip, "-exist")
	return cmd.Run()
}

// resetStore periodically resets per-IP counters.
func resetStore() {
	for {
		time.Sleep(5 * time.Second)
		store.IterateOverIPs(func(ip string, data *Ipin) {
			if data.Lastseen.Before(time.Now().Add(-90 * time.Second)) {
				data.Delete = true
			} else {
				data.PPS = 0
				data.Data = 0
				data.SYN = 0
				data.Mac1 = ""
				data.Mac2 = ""
				data.Mac3 = ""
			}
		})
	}
}

// ------------------------
// TCP Proxy Section
// ------------------------

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientAddr := client.RemoteAddr().String()
	clientIP := strings.Split(clientAddr, ":")[0]

	// Check if banned.
	bannedIPsMu.RLock()
	if banned, exists := bannedIPs[clientIP]; exists && banned {
		bannedIPsMu.RUnlock()
		log.Printf("[TCP] Dropping connection from banned IP %s", clientIP)
		client.Close()
		return
	}
	bannedIPsMu.RUnlock()

	// Update active connection and per-IP store.
	activeTCPMu.Lock()
	activeTCP[clientIP] = true
	activeTCPMu.Unlock()
	defer func() {
		activeTCPMu.Lock()
		delete(activeTCP, clientIP)
		activeTCPMu.Unlock()
	}()

	// Update overall counters.
	atomic.AddInt64(&tcpConnCount, 1)
	ipEventCountsMu.Lock()
	ipEventCounts[clientIP]++
	ipEventCountsMu.Unlock()

	// Smart protection via store.
	ipRec := store.GetOrCreateIPData(clientIP)
	ipRec.Lock.Lock()
	ipRec.Data.Lastseen = time.Now()
	if ipRec.Data.Blocked {
		ipRec.Lock.Unlock()
		client.Close()
		return
	}
	// Read initial data (if any) for additional checks.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	if err == nil && n > 0 {
		// Log the initial data (up to 64 bytes).
		log.Printf("[TCP] Initial packet from %s: %q", clientAddr, string(buf[:min(n, 64)]))
		// Accumulate data size.
		ipRec.Data.Data += int64(n)
		// Smart check: if TCP data exceeds threshold.
		if btom(ipRec.Data.Data) > TCPDataThresholdMB {
			ipRec.Data.OffenseCount++
			if time.Since(ipRec.Data.FirstSeen) >= gracePeriod && ipRec.Data.OffenseCount >= maxOffense {
				banIP(clientIP)
				ipRec.Data.Blocked = true
				ipRec.Lock.Unlock()
				client.Close()
				return
			}
		}
	} else if err != nil && err != io.EOF {
		log.Printf("[TCP] Error reading from %s: %v", clientAddr, err)
		ipRec.Lock.Unlock()
		client.Close()
		return
	}
	ipRec.Lock.Unlock()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
		client.Close()
		return
	}
	defer backend.Close()

	// Send initial data if any.
	if n > 0 {
		_, _ = backend.Write(buf[:n])
	}

	// Proxy data bidirectionally.
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
		log.Fatalf("[TCP] Error starting listener on port %s: %v", listenPort, err)
	}
	defer ln.Close()
	log.Printf("[TCP] Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP] Accept error: %v", err)
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
			log.Printf("[UDP] Read error: %v", err)
			continue
		}
		clientKey := clientAddr.String()
		clientIP := strings.Split(clientKey, ":")[0]
		uniqueIPs.Store(clientIP, true)
		// Count event only if no active TCP exists.
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

		// Smart protection update for UDP.
		ipRec := store.GetOrCreateIPData(clientIP)
		ipRec.Lock.Lock()
		ipRec.Data.Lastseen = time.Now()
		ipRec.Data.Data += int64(n)
		if btom(ipRec.Data.Data) > UDPDataThresholdMB {
			ipRec.Data.OffenseCount++
			if time.Since(ipRec.Data.FirstSeen) >= gracePeriod && ipRec.Data.OffenseCount >= maxOffense {
				banIP(clientIP)
				ipRec.Data.Blocked = true
				ipRec.Lock.Unlock()
				continue
			}
		}
		ipRec.Lock.Unlock()

		atomic.AddInt64(&udpPacketCount, 1)
		mu.Lock()
		entry, found := backendMap[clientKey]
		if !found {
			targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
			if err != nil {
				log.Printf("[UDP] Error resolving target address: %v", err)
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
// Main Function
// ------------------------

func main() {
	// Read pterodactyl (or custom) variables via flags.
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL for DDoS alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	// Ensure required ipsets exist.
	if err := ensureIPSet("whitelist"); err != nil {
		log.Fatalf("Failed to ensure ipset 'whitelist': %v", err)
	}
	if err := ensureIPSet("backends"); err != nil {
		log.Fatalf("Failed to ensure ipset 'backends': %v", err)
	}
	if err := ensureIPSet("banlist_perm"); err != nil {
		log.Fatalf("Failed to ensure ipset 'banlist_perm': %v", err)
	}

	// Start background routines.
	go func() {
		ticker := time.NewTicker(IntervalDuration)
		defer ticker.Stop()
		for range ticker.C {
			processInterval(*discordWebhook)
		}
	}()
	go resetStore()

	// Start proxy servers.
	go startTCPProxy(*listenPort, *targetIP, *targetPort)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

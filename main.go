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
// Global counters and maps for DDoS detection
// ------------------------

var (
	tcpConnCount   int64    // counts TCP connections in current interval
	udpPacketCount int64    // counts UDP packets in current interval
	uniqueIPs      sync.Map // map[string]bool of client IPs seen in current interval

	// For per-IP event counting
	ipEventCounts sync.Map // map[string]*int64

	// Banned IPs: if an IP exceeds the per-IP threshold, it is banned.
	bannedIPs sync.Map // map[string]bool

	// activeTCP tracks IPs with active TCP connections.
	activeTCP sync.Map // map[string]bool

	attackMode      bool
	attackModeLock  sync.Mutex
	peakEvents      int64 // peak events in any interval during attack
	consecutiveSafe int   // number of consecutive intervals below overall threshold
)

// Global thresholds.
const (
	thresholdEvents   int64 = 100  // overall events in an interval to trigger DDoS mode (only if >1 unique IP)
	ipThresholdMulti  int64 = 200  // per-IP threshold when multiple clients exist
	ipThresholdSingle int64 = 500  // per-IP threshold when only one client is present
)

// incrementIPEvent increments the counter for a given IP.
func incrementIPEvent(ip string) {
	v, _ := ipEventCounts.LoadOrStore(ip, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

// offender represents an IP and its event count.
type offender struct {
	IP    string
	Count int64
}

// monitorAttack runs every 5 seconds to check event counts and ban offenders.
func monitorAttack(discordWebhook string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tcp := atomic.SwapInt64(&tcpConnCount, 0)
		udp := atomic.SwapInt64(&udpPacketCount, 0)
		total := tcp + udp

		uniqueCount := 0
		uniqueIPs.Range(func(key, value interface{}) bool {
			uniqueCount++
			return true
		})
		uniqueIPs = sync.Map{}

		// Build per-IP summary.
		var offenders []offender
		ipEventCounts.Range(func(key, value interface{}) bool {
			count := atomic.LoadInt64(value.(*int64))
			offenders = append(offenders, offender{
				IP:    key.(string),
				Count: count,
			})
			return true
		})
		ipEventCounts = sync.Map{}

		// Sort offenders descending by count.
		sort.Slice(offenders, func(i, j int) bool {
			return offenders[i].Count > offenders[j].Count
		})

		// Ban IPs based on thresholds.
		for _, off := range offenders {
			if uniqueCount > 1 {
				if off.Count > ipThresholdMulti {
					bannedIPs.Store(off.IP, true)
					log.Printf("BANNED: IP %s banned with %d events", off.IP, off.Count)
				}
			} else { // single IP scenario
				if off.Count > ipThresholdSingle {
					bannedIPs.Store(off.IP, true)
					log.Printf("BANNED: IP %s banned with %d events (single client)", off.IP, off.Count)
				}
			}
		}

		// Log interval summary.
		log.Printf("=== Interval Summary ===")
		log.Printf("TCP: %d | UDP: %d | Total: %d | Unique IPs: %d", tcp, udp, total, uniqueCount)
		log.Printf("Top Offenders:")
		for i, off := range offenders {
			if i >= 3 {
				break
			}
			log.Printf("  %s : %d events", off.IP, off.Count)
		}

		attackModeLock.Lock()
		// Trigger attack mode only if there's more than one unique IP.
		if uniqueCount > 1 && !attackMode && total > thresholdEvents {
			attackMode = true
			peakEvents = total
			consecutiveSafe = 0
			log.Printf(">>> DDOS attack detected. Server mitigation enabled.")
			sendDiscordEmbed(discordWebhook, "Server Mitigation Enabled",
				fmt.Sprintf("DDoS attack detected.\nTotal events: %d\nUnique IPs: %d", total, uniqueCount), 0xff6600)
		} else if attackMode {
			if total > peakEvents {
				peakEvents = total
			}
			if total < thresholdEvents {
				consecutiveSafe++
			} else {
				consecutiveSafe = 0
			}
			if consecutiveSafe >= 2 {
				attackMode = false
				msg := fmt.Sprintf("Attack ended.\nPeak events: %d\nUnique IPs (last interval): %d", peakEvents, uniqueCount)
				log.Printf(">>> DDOS attack ended. %s", msg)
				sendDiscordEmbed(discordWebhook, "Attack Ended", msg, 0x00bfff)
				peakEvents = 0
				consecutiveSafe = 0
			}
		}
		attackModeLock.Unlock()
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

	atomic.AddInt64(&tcpConnCount, 1)
	uniqueIPs.Store(clientIP, true)
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
		atomic.AddInt64(&udpPacketCount, 1)
		clientKey := clientAddr.String()
		clientIP := strings.Split(clientKey, ":")[0]
		uniqueIPs.Store(clientIP, true)
		// Only count UDP events if there's no active TCP connection from this IP.
		if _, active := activeTCP.Load(clientIP); !active {
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
	discordWebhook := flag.String("discordWebhook", "", "Discord webhook URL for DDOS alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	go monitorAttack(*discordWebhook)
	go startTCPProxy(*listenPort, *targetIP, *targetPort)
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

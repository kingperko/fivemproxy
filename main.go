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
// Global counters for attack detection
// ------------------------

var (
	tcpConnCount   int64    // counts TCP connections in current interval
	udpPacketCount int64    // counts UDP packets in current interval
	uniqueIPs      sync.Map // map[string]bool of client IPs seen in current interval

	attackMode      bool
	attackModeLock  sync.Mutex
	peakEvents      int64 // peak events (TCP+UDP) in any interval during attack
	consecutiveSafe int   // number of consecutive intervals below threshold
)

// Increase threshold to allow normal FiveM traffic.
const thresholdEvents int64 = 1000

// monitorAttack runs every 5 seconds to check event counts.
func monitorAttack(discordWebhook string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		// Atomically read and reset counters.
		tcp := atomic.SwapInt64(&tcpConnCount, 0)
		udp := atomic.SwapInt64(&udpPacketCount, 0)
		total := tcp + udp

		uniqueCount := 0
		uniqueIPs.Range(func(key, value interface{}) bool {
			uniqueCount++
			return true
		})
		uniqueIPs = sync.Map{}

		log.Printf("=== Interval Summary ===")
		log.Printf("TCP connections: %d | UDP packets: %d | Total events: %d | Unique IPs: %d",
			tcp, udp, total, uniqueCount)

		attackModeLock.Lock()
		if !attackMode && total > thresholdEvents {
			attackMode = true
			peakEvents = total
			consecutiveSafe = 0
			log.Printf(">>> Server mitigation enabled: High load detected. DDOS attack suspected.")
			sendDiscordEmbed(discordWebhook, "Server Mitigation Enabled",
				"You are currently receiving a DDoS attack. We will let you know when it’s over.", 0xff6600)
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
				msg := fmt.Sprintf("Attack ended.\nPeak events in an interval: %d\nUnique IPs (last interval): %d", peakEvents, uniqueCount)
				log.Printf(">>> DDOS attack mitigated. %s", msg)
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
	log.Printf("[TCP] Accepted connection from %s", clientAddr)
	atomic.AddInt64(&tcpConnCount, 1)
	uniqueIPs.Store(clientIP, true)
	defer client.Close()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
		return
	}
	defer backend.Close()

	// Attempt to read an initial packet for logging without forcing closure.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{}) // Clear deadline
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("[TCP] No initial packet received from %s (timeout)", clientAddr)
		} else if err != io.EOF {
			log.Printf("[TCP] Error reading initial data from %s: %v", clientAddr, err)
		}
	}
	if n > 0 {
		log.Printf("[TCP] Initial packet from %s: %q", clientAddr, string(buf[:min(n, 64)]))
		_, _ = backend.Write(buf[:n])
	}

	// Use WaitGroup to handle bidirectional copying.
	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from client to backend.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(backend, client)
		if tcpBackend, ok := backend.(*net.TCPConn); ok {
			tcpBackend.CloseWrite()
		} else {
			backend.Close()
		}
	}()

	// Copy from backend to client.
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, backend)
		if tcpClient, ok := client.(*net.TCPConn); ok {
			tcpClient.CloseWrite()
		} else {
			client.Close()
		}
	}()

	wg.Wait()
	log.Printf("[TCP] Connection from %s closed after %v", clientAddr, time.Since(startTime))
}

func startTCPProxy(listenPort, targetIP, targetPort string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[TCP] Error starting TCP listener on port %s: %v", listenPort, err)
	}
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

type udpMapEntry struct {
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

	backendMap := make(map[string]*udpMapEntry)
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
		uniqueIPs.Store(strings.Split(clientKey, ":")[0], true)

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
			entry = &udpMapEntry{
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
			}(clientAddr, bc, clientKey)
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

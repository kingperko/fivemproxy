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

type discordEmbed struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
}

type discordWebhookBody struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

// sendDiscordEmbed sends a brief, formatted message to Discord.
func sendDiscordEmbed(webhookURL, title, description string, color int) {
	if webhookURL == "" {
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
		log.Printf(">> [DISCORD] JSON marshal error: %v", err)
		return
	}
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf(">> [DISCORD] Request creation error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf(">> [DISCORD] Request error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf(">> [DISCORD] Unexpected status code: %d", resp.StatusCode)
	}
}

// ------------------------
// Global Variables & Helpers
// ------------------------

var (
	// Whitelisted IPs are allowed to pass without further checks.
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	// Banned IPs (suspicious connections) are blocked immediately.
	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	// A simple TCP connection counter.
	tcpConnCount int64
)

// updateWhitelist adds an IP to the whitelist.
func updateWhitelist(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

// isWhitelisted returns true if the IP is already whitelisted.
func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

// banIP adds an IP to the banned list.
func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// isBanned checks if an IP is banned.
func isBanned(ip string) bool {
	bannedIPsMu.RLock()
	defer bannedIPsMu.RUnlock()
	return bannedIPs[ip]
}

// ------------------------
// Handshake Detection
// ------------------------

// isLegitHandshake returns true if the data is recognized as TLS or known plaintext.
func isLegitHandshake(data []byte) bool {
	// Check for TLS handshake: record type 0x16 with version 0x03 and version byte 0x00-0x03.
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
	// Check for known plaintext keywords (info.json, players.json, etc.).
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client") {
		return true
	}
	return false
}

// ------------------------
// TCP Proxy Logic
// ------------------------

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Immediately drop if IP is banned.
	if isBanned(clientIP) {
		log.Printf(">> [TCP] Dropped connection from banned IP %s", clientIP)
		return
	}

	// If already whitelisted, just proxy.
	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Set a short deadline to read the initial handshake.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf(">> [TCP] [%s] Error reading handshake: %v", clientIP, err)
		banIP(clientIP)
		sendDiscordEmbed(discordWebhook, "Proxy Alert", "Suspicious TCP handshake detected. Connection dropped.", 0xff0000)
		return
	}

	// Check handshake validity.
	if !isLegitHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Dropped - Invalid handshake", clientIP)
		banIP(clientIP)
		sendDiscordEmbed(discordWebhook, "Proxy Alert", "Suspicious TCP handshake detected. Connection dropped.", 0xff0000)
		return
	}

	// Valid handshake: whitelist and proxy.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	defer backendConn.Close()

	// Forward the initial handshake data to the backend.
	backendConn.Write(buf[:n])
	proxyTCPWithConn(conn, backendConn, clientIP)
}

// proxyTCP establishes a backend connection and pipes data.
func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] Backend dial error: %v", err)
		return
	}
	defer backendConn.Close()
	proxyTCPWithConn(client, backendConn, client.RemoteAddr().String())
}

// proxyTCPWithConn pipes data between two connections.
func proxyTCPWithConn(client, backend net.Conn, clientIP string) {
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
	log.Printf(">> [TCP] [%s] Connection closed", clientIP)
}

// ------------------------
// UDP Proxy Logic
// ------------------------

// We keep a map of client addresses -> persistent backend connections.
type udpMapping struct {
	backendConn *net.UDPConn
	lastSeen    time.Time
}

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	addr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving listen address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf(">> [UDP] Error starting UDP listener on port %s: %v", listenPort, err)
	}
	defer conn.Close()
	log.Printf(">> [UDP] Listening on port %s", listenPort)

	var mu sync.Mutex
	backendMap := make(map[string]*udpMapping) // key: clientAddr.String()

	// Goroutine to periodically clean up old mappings.
	go func() {
		for {
			time.Sleep(60 * time.Second)
			mu.Lock()
			for key, mapping := range backendMap {
				if time.Since(mapping.lastSeen) > 5*time.Minute {
					log.Printf(">> [UDP] Closing stale connection for %s", key)
					mapping.backendConn.Close()
					delete(backendMap, key)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf(">> [UDP] Read error: %v", err)
			continue
		}
		clientIP := clientAddr.IP.String()

		// Drop packet if IP is banned.
		if isBanned(clientIP) {
			log.Printf(">> [UDP] Dropped packet from banned IP %s", clientIP)
			continue
		}

		// If not whitelisted, check handshake. If invalid, ban.
		if !isWhitelisted(clientIP) {
			if !isLegitHandshake(buf[:n]) {
				log.Printf(">> [UDP] Dropped packet from %s - invalid handshake", clientIP)
				banIP(clientIP)
				sendDiscordEmbed(discordWebhook, "Proxy Alert", "Suspicious UDP packet detected. Connection dropped.", 0xff0000)
				continue
			}
			updateWhitelist(clientIP)
			log.Printf(">> [UDP] [%s] Whitelisted via UDP handshake", clientIP)
		}

		// Now forward to backend, but first we need a persistent backendConn for this client.
		clientKey := clientAddr.String()
		mu.Lock()
		mapping, found := backendMap[clientKey]
		if !found {
			// Create a new backend connection for this client.
			backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
			if err != nil {
				mu.Unlock()
				log.Printf(">> [UDP] Error resolving backend address: %v", err)
				continue
			}
			bc, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				mu.Unlock()
				log.Printf(">> [UDP] Error dialing backend for %s: %v", clientKey, err)
				continue
			}

			mapping = &udpMapping{
				backendConn: bc,
				lastSeen:    time.Now(),
			}
			backendMap[clientKey] = mapping

			// Start a reader goroutine for the backend -> client traffic.
			go func(cKey string, cAddr *net.UDPAddr, bc *net.UDPConn) {
				respBuf := make([]byte, 2048)
				for {
					bc.SetReadDeadline(time.Now().Add(5 * time.Minute))
					n2, _, err2 := bc.ReadFromUDP(respBuf)
					if err2 != nil {
						// Any error closes this mapping
						log.Printf(">> [UDP] Closing connection for %s: %v", cKey, err2)
						bc.Close()
						mu.Lock()
						delete(backendMap, cKey)
						mu.Unlock()
						return
					}
					// Forward the data back to the client
					conn.WriteToUDP(respBuf[:n2], cAddr)
				}
			}(clientKey, clientAddr, bc)
		}
		// Update lastSeen
		mapping.lastSeen = time.Now()
		bc := mapping.backendConn
		mu.Unlock()

		// Send the client packet to the backend.
		_, err = bc.Write(buf[:n])
		if err != nil {
			log.Printf(">> [UDP] Write to backend error: %v", err)
			continue
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
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	log.Printf(">> [INFO] Starting proxy: forwarding to %s:%s on port %s", *targetIP, *targetPort, *listenPort)

	// Start TCP proxy in a goroutine.
	go func() {
		ln, err := net.Listen("tcp", ":"+*listenPort)
		if err != nil {
			log.Fatalf(">> [TCP] Listen error on port %s: %v", *listenPort, err)
		}
		defer ln.Close()
		log.Printf(">> [TCP] Listening on port %s", *listenPort)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf(">> [TCP] Accept error: %v", err)
				continue
			}
			go handleTCPConnection(conn, *targetIP, *targetPort, *discordWebhook)
		}
	}()

	// Start UDP prxy (runs in main goroutine).
	startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)
}

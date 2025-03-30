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

	// A simple TCP connection counter (for reference/logging).
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

// ------------------------
// Handshake Detection
// ------------------------

// isLegitHandshake returns true if the data indicates a
// TLS handshake (common for FiveM) or known plaintext keywords.
func isLegitHandshake(data []byte) bool {
	// Check for TLS handshake: record type 0x16 with version 0x03 and version byte 0x00-0x03.
	if len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && (data[2] >= 0x00 && data[2] <= 0x03) {
		return true
	}
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
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf(">> [TCP] Dropped connection from banned IP %s", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	// If already whitelisted, just proxy.
	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Set a short deadline to read the initial handshake.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
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

	// Forward the handshake to the backend.
	_, _ = backendConn.Write(buf[:n])
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

	backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving backend address: %v", err)
	}

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf(">> [UDP] Read error: %v", err)
			continue
		}
		clientIP := clientAddr.IP.String()

		// Drop packet if IP is banned.
		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			log.Printf(">> [UDP] Dropped packet from banned IP %s", clientIP)
			continue
		}
		bannedIPsMu.RUnlock()

		// Drop packet if IP is not whitelisted.
		if !isWhitelisted(clientIP) {
			log.Printf(">> [UDP] Dropped packet from %s - not whitelisted", clientIP)
			continue
		}

		// Forward packet to backend.
		backendConn, err := net.DialUDP("udp", nil, backendAddr)
		if err != nil {
			log.Printf(">> [UDP] Backend dial error: %v", err)
			continue
		}
		_, err = backendConn.Write(buf[:n])
		if err != nil {
			log.Printf(">> [UDP] Write to backend error: %v", err)
			backendConn.Close()
			continue
		}

		// Attempt to read response from backend.
		respBuf := make([]byte, 2048)
		backendConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n2, err := backendConn.Read(respBuf)
		backendConn.Close()
		if err != nil {
			log.Printf(">> [UDP] Read from backend error: %v", err)
			continue
		}

		// Send response back to client.
		_, err = conn.WriteToUDP(respBuf[:n2], clientAddr)
		if err != nil {
			log.Printf(">> [UDP] Write to client error: %v", err)
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

	// Start UDP proxy (runs in main goroutine).
	startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)
}

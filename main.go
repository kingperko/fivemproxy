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
	whitelistedIPs   = make(map[string]bool)
	whitelistedIPsMu sync.RWMutex

	bannedIPs   = make(map[string]bool)
	bannedIPsMu sync.RWMutex

	tcpConnCount int64
)

func updateWhitelist(ip string) {
	whitelistedIPsMu.Lock()
	whitelistedIPs[ip] = true
	whitelistedIPsMu.Unlock()
}

func isWhitelisted(ip string) bool {
	whitelistedIPsMu.RLock()
	defer whitelistedIPsMu.RUnlock()
	return whitelistedIPs[ip]
}

func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// ------------------------
// Handshake Detection
// ------------------------

func isLegitHandshake(data []byte) bool {
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

	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf(">> [TCP] Dropped connection from banned IP %s", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

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

	if !isLegitHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Dropped - Invalid handshake", clientIP)
		banIP(clientIP)
		sendDiscordEmbed(discordWebhook, "Proxy Alert", "Suspicious TCP handshake detected. Connection dropped.", 0xff0000)
		return
	}

	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	defer backendConn.Close()

	backendConn.Write(buf[:n])
	proxyTCPWithConn(conn, backendConn, clientIP)
}

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] Backend dial error: %v", err)
		return
	}
	defer backendConn.Close()
	proxyTCPWithConn(client, backendConn, client.RemoteAddr().String())
}

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
// UDP Proxy Logic (Persistent Sessions)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr    // Client address
	backendConn *net.UDPConn    // Persistent connection to backend for this client
	lastActive  time.Time       // Last time this session was used
	closeOnce   sync.Once       // To ensure session cleanup happens once
}

var (
	sessionMap   = make(map[string]*sessionData)
	sessionMu    sync.Mutex
	cleanupTimer = 30 * time.Second  // Cleanup check frequency
	sessionTTL   = 120 * time.Second // Session idle timeout
)

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	listenAddr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving listen address: %v", err)
	}
	listenConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Fatalf(">> [UDP] Error starting UDP listener on port %s: %v", listenPort, err)
	}
	log.Printf(">> [UDP] Listening on port %s", listenPort)

	backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf(">> [UDP] Error resolving backend address: %v", err)
	}

	// Start cleanup goroutine.
	go cleanupSessions()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
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

		// Check handshake for new sessions.
		if !isWhitelisted(clientIP) && !isLegitHandshake(buf[:n]) {
			log.Printf(">> [UDP] Dropped packet from %s - invalid handshake", clientIP)
			banIP(clientIP)
			sendDiscordEmbed(discordWebhook, "Proxy Alert", "Suspicious UDP packet detected. Connection dropped.", 0xff0000)
			continue
		}
		// Whitelist if not already.
		if !isWhitelisted(clientIP) {
			updateWhitelist(clientIP)
			log.Printf(">> [UDP] [%s] Whitelisted via UDP handshake", clientIP)
		}

		// Get or create a persistent session.
		sessionMu.Lock()
		sd, exists := sessionMap[clientAddr.String()]
		if !exists {
			backendConn, err := net.DialUDP("udp", nil, backendAddr)
			if err != nil {
				sessionMu.Unlock()
				log.Printf(">> [UDP] Error dialing backend for client %s: %v", clientIP, err)
				continue
			}
			sd = &sessionData{
				clientAddr:  clientAddr,
				backendConn: backendConn,
				lastActive:  time.Now(),
			}
			sessionMap[clientAddr.String()] = sd
			go handleUDPSession(listenConn, sd)
		} else {
			sd.lastActive = time.Now()
		}
		sessionMu.Unlock()

		// Forward the client's packet to its persistent backend connection.
		_, err = sd.backendConn.Write(buf[:n])
		if err != nil {
			log.Printf(">> [UDP] Write to backend error for client %s: %v", clientIP, err)
			continue
		}
	}
}

// handleUDPSession continuously reads from the backend connection for a given session
// and forwards responses to the client.
func handleUDPSession(listenConn *net.UDPConn, sd *sessionData) {
	buf := make([]byte, 2048)
	for {
		sd.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sd.backendConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Continue waiting for data.
				continue
			}
			log.Printf(">> [UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		// Forward the response back to the client.
		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil {
			log.Printf(">> [UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
	// On error or closure, clean up the session.
	cleanupSession(sd.clientAddr.String())
}

// cleanupSessions periodically removes sessions that have been idle too long.
func cleanupSessions() {
	ticker := time.NewTicker(cleanupTimer)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sessionMu.Lock()
		for key, sd := range sessionMap {
			if now.Sub(sd.lastActive) > sessionTTL {
				log.Printf(">> [UDP] Closing idle session for client %s", sd.clientAddr)
				cleanupSession(key)
			}
		}
		sessionMu.Unlock()
	}
}

// cleanupSession closes and removes a session.
func cleanupSession(key string) {
	sessionMu.Lock()
	sd, exists := sessionMap[key]
	if exists {
		delete(sessionMap, key)
		sd.closeOnce.Do(func() {
			sd.backendConn.Close()
		})
	}
	sessionMu.Unlock()
}

// ------------------------
// Utility Functions
// ------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

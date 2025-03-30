// If you understand and want to proceed, repeat the command including --classic.
// For example, if installing Go via snap:
//     sudo snap install go --classic
// Then run your program with:
//     go run main.go -targetIP=<BACKEND_IP> -targetPort=<BACKEND_PORT> -listenPort=<PROXY_PORT> [-discordWebhook=<WEBHOOK_URL>]

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ------------------------
// Custom Structured Logging
// ------------------------

type LogLevel string

const (
	INFO  LogLevel = "INFO"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

func logMsg(level LogLevel, msg string) {
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] [%s] %s\n", now, level, msg)
}

func logInfo(msg string) {
	logMsg(INFO, msg)
}

func logWarn(msg string) {
	logMsg(WARN, msg)
}

func logError(msg string) {
	logMsg(ERROR, msg)
}

// ------------------------
// Discord Notification (Optional)
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

func sendDiscordNotification(webhookURL, title, description string, color int) {
	if webhookURL == "" {
		return
	}
	embed := discordEmbed{
		Title:       title,
		Description: description,
		Color:       color,
	}
	payload := discordWebhookBody{
		Username: "Lightweight DDOS Protection - YourBrand",
		Embeds:   []discordEmbed{embed},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logError(fmt.Sprintf("[DISCORD] JSON marshal error: %v", err))
		return
	}
	req, err := http.NewRequest("POST", webhookURL, strings.NewReader(string(data)))
	if err != nil {
		logError(fmt.Sprintf("[DISCORD] Request creation error: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logError(fmt.Sprintf("[DISCORD] Error sending notification: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		logError(fmt.Sprintf("[DISCORD] Webhook returned status: %d", resp.StatusCode))
	}
}

// ------------------------
// IP Tracking & Rate Limiting
// ------------------------

type IPState int

const (
	Unknown IPState = iota
	Whitelisted
	Blocked
)

type IPInfo struct {
	State         IPState
	ConnCount     int       // active TCP connection count
	FirstSeen     time.Time // when first seen
	NewConnBurst  int       // count of new connections in a burst
	LastBurstTime time.Time // when burst counter was last reset
}

type IPStore struct {
	sync.Mutex
	data map[string]*IPInfo
}

func newIPStore() *IPStore {
	return &IPStore{
		data: make(map[string]*IPInfo),
	}
}

func (s *IPStore) getOrCreate(ip string) *IPInfo {
	s.Lock()
	defer s.Unlock()
	info, ok := s.data[ip]
	if !ok {
		info = &IPInfo{
			State:     Unknown,
			FirstSeen: time.Now(),
		}
		s.data[ip] = info
	}
	return info
}

func (s *IPStore) setState(ip string, state IPState) {
	s.Lock()
	defer s.Unlock()
	if info, ok := s.data[ip]; ok {
		info.State = state
	} else {
		s.data[ip] = &IPInfo{State: state, FirstSeen: time.Now()}
	}
}

var ipStore = newIPStore()

func banIP(ip, reason, discordWebhook string) {
	ipStore.setState(ip, Blocked)
	logWarn(fmt.Sprintf("BANNED: IP %s blocked. Reason: %s", ip, reason))
	go sendDiscordNotification(discordWebhook, "IP Banned", fmt.Sprintf("IP: %s\nReason: %s", ip, reason), 0xff0000)
}

// ------------------------
// Heuristic HTTP Request Check
// ------------------------

func isValidHTTPHeader(data []byte) bool {
	header := string(data)
	validMethods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS "}
	methodValid := false
	for _, m := range validMethods {
		if strings.HasPrefix(header, m) {
			methodValid = true
			break
		}
	}
	if !methodValid {
		return false
	}
	// Check for key headers.
	if !strings.Contains(header, "Host:") || !strings.Contains(header, "User-Agent:") {
		return false
	}
	if !(strings.Contains(header, "HTTP/1.1") || strings.Contains(header, "HTTP/1.0")) {
		return false
	}
	return true
}

// ------------------------
// TCP Proxy with HTTP Heuristics
// ------------------------

const readTimeout = 3 * time.Second

const (
	maxNewConnBurst    = 10              // max new connections from an unknown IP in burst window
	burstWindow        = 5 * time.Second // duration for burst window
	maxConcurrentConns = 5               // max concurrent connections per IP
)

func handleTCPConnection(client net.Conn, targetIP, targetPort, discordWebhook string) {
	defer client.Close()
	clientAddr := client.RemoteAddr().String()
	ip := strings.Split(clientAddr, ":")[0]
	info := ipStore.getOrCreate(ip)

	if info.State == Blocked {
		logWarn(fmt.Sprintf("[TCP] Dropping connection from blocked IP %s", ip))
		return
	}

	// Rate limit new connections.
	now := time.Now()
	ipStore.Lock()
	if now.Sub(info.LastBurstTime) > burstWindow {
		info.NewConnBurst = 0
		info.LastBurstTime = now
	}
	info.NewConnBurst++
	currentBurst := info.NewConnBurst
	ipStore.Unlock()
	if info.State == Unknown && currentBurst > maxNewConnBurst {
		banIP(ip, "Excessive connection bursts", discordWebhook)
		return
	}

	// Increment concurrent connection count.
	ipStore.Lock()
	info.ConnCount++
	currentConns := info.ConnCount
	ipStore.Unlock()
	defer func() {
		ipStore.Lock()
		info.ConnCount--
		ipStore.Unlock()
	}()
	if currentConns > maxConcurrentConns {
		banIP(ip, fmt.Sprintf("Too many concurrent connections (%d)", currentConns), discordWebhook)
		return
	}

	// Read initial data.
	client.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 512)
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{})
	if err != nil {
		logError(fmt.Sprintf("[TCP] Error reading from %s: %v", ip, err))
		return
	}
	if n == 0 {
		logWarn(fmt.Sprintf("[TCP] Received zero bytes from %s", ip))
		return
	}
	initialData := buf[:n]
	if !isValidHTTPHeader(initialData) {
		banIP(ip, "Invalid HTTP header", discordWebhook)
		return
	}

	// Mark IP as whitelisted.
	ipStore.setState(ip, Whitelisted)
	logInfo(fmt.Sprintf("[TCP] Whitelisted IP %s after valid HTTP handshake", ip))
	forwardTCPWithInitial(client, targetIP, targetPort, initialData)
}

func forwardTCPWithInitial(client net.Conn, targetIP, targetPort string, initial []byte) {
	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		logError(fmt.Sprintf("[TCP] Error connecting to backend: %v", err))
		return
	}
	defer backend.Close()
	if len(initial) > 0 {
		backend.Write(initial)
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
}

func startTCPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		logError(fmt.Sprintf("[TCP] Listen error on port %s: %v", listenPort, err))
		os.Exit(1)
	}
	defer ln.Close()
	logInfo(fmt.Sprintf("[TCP] Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort))
	for {
		conn, err := ln.Accept()
		if err != nil {
			logWarn(fmt.Sprintf("[TCP] Accept error: %v", err))
			continue
		}
		go handleTCPConnection(conn, targetIP, targetPort, discordWebhook)
	}
}

// ------------------------
// UDP Proxy (Only forward from whitelisted IPs)
// ------------------------

type udpEntry struct {
	backendConn *net.UDPConn
	lastSeen    time.Time
}

func startUDPProxy(listenPort, targetIP, targetPort, discordWebhook string) {
	addr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		logError(fmt.Sprintf("[UDP] Resolve error: %v", err))
		os.Exit(1)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		logError(fmt.Sprintf("[UDP] Listen error on port %s: %v", listenPort, err))
		os.Exit(1)
	}
	defer conn.Close()
	logInfo(fmt.Sprintf("[UDP] Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort))
	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		logError(fmt.Sprintf("[UDP] Could not resolve backend %s:%s: %v", targetIP, targetPort, err))
		os.Exit(1)
	}
	backendMap := make(map[string]*udpEntry)
	var mu sync.Mutex
	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logWarn(fmt.Sprintf("[UDP] Read error: %v", err))
			continue
		}
		ip := clientAddr.IP.String()
		info := ipStore.getOrCreate(ip)
		if info.State != Whitelisted {
			logWarn(fmt.Sprintf("[UDP] Dropping packet from non-whitelisted IP %s", ip))
			continue
		}
		mu.Lock()
		entry, found := backendMap[clientAddr.String()]
		if !found {
			bc, err := net.DialUDP("udp", nil, targetAddr)
			if err != nil {
				logError(fmt.Sprintf("[UDP] Dial error: %v", err))
				mu.Unlock()
				continue
			}
			entry = &udpEntry{backendConn: bc, lastSeen: time.Now()}
			backendMap[clientAddr.String()] = entry
			go func(ca *net.UDPAddr, bc *net.UDPConn, key string) {
				backendBuf := make([]byte, 2048)
				for {
					bc.SetReadDeadline(time.Now().Add(2 * time.Minute))
					n2, _, err2 := bc.ReadFromUDP(backendBuf)
					if err2 != nil {
						bc.Close()
						mu.Lock()
						delete(backendMap, key)
						mu.Unlock()
						return
					}
					conn.WriteToUDP(backendBuf[:n2], ca)
				}
			}(clientAddr, bc, clientAddr.String())
		}
		entry.lastSeen = time.Now()
		_, _ = entry.backendConn.Write(buf[:n])
		mu.Unlock()
	}
}

// ------------------------
// MAIN
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

	go startTCPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)
	startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)
}

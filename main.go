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
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ------------------------
// Discord Notification Support
// ------------------------

// Set this to true to disable Discord notifications (for now).
const disableDiscord = true

// Added flag to disable UDP handshake check.
const disableUDPHandshakeCheck = true

// discordEmbed defines the structure of a Discord embed.
type discordEmbed struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
}

// discordWebhookBody defines the structure of the webhook payload.
type discordWebhookBody struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

func sendDiscordEmbed(webhookURL, title, description string, color int) {
	if disableDiscord || webhookURL == "" {
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

func sendDDoSAttackStarted(webhookURL, serverName, serverIP, currentMetrics, attackMethod, targetPort string) {
	title := "Perko's Proxy"
	description := ":rotating_light: DDoS Attack Started\n" +
		"A potential DDoS attack has been detected.\n\n" +
		"**Server**\n" + serverName + " - " + serverIP + "\n" +
		"**Current Metrics**\n" + currentMetrics + "\n" +
		"**Attack Method**\n" + attackMethod + "\n" +
		"**Target Port**\n" + targetPort
	sendDiscordEmbed(webhookURL, title, description, 0xff0000)
}

func sendDDoSAttackEnded(webhookURL, serverName, serverIP, peakMetrics, firewallStats, attackMethod, targetPort string) {
	title := "Perko's Proxy"
	description := ":white_check_mark: DDoS Attack Ended\n" +
		"The attack has ended. Final recorded metrics:\n\n" +
		"**Server**\n" + serverName + " - " + serverIP + "\n" +
		"**Peak Metrics**\n" + peakMetrics + "\n" +
		"**Firewall Stats**\n" + firewallStats + "\n" +
		"**Attack Method**\n" + attackMethod + "\n" +
		"**Target Port**\n" + targetPort
	sendDiscordEmbed(webhookURL, title, description, 0x00ff00)
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

// In this version, we log handshake errors rather than banning immediately.
func banIP(ip string) {
	bannedIPsMu.Lock()
	bannedIPs[ip] = true
	bannedIPsMu.Unlock()
}

// ------------------------
// DDoS Global Variables
// ------------------------

var (
	ddosMutex        sync.Mutex
	ddosPacketCount  uint64
	ddosByteCount    uint64
	ddosAttackActive bool
)

// ------------------------
// Handshake Detection
// ------------------------

func isTCPHandshake(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] >= 0x00 && data[2] <= 0x03)
}

func isFiveMHandshake(data []byte) bool {
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "get /info.json") ||
		strings.Contains(lower, "get /players.json") ||
		strings.Contains(lower, "post /client")
}

// ------------------------
// TCP Proxy Logic
// ------------------------

// forward implements data copying between two connections.
// The "boo" flag applies a temporary read deadline for the first few packets.
// The "mytype" parameter allows you to perform packet size checks.
func forward(source, destination net.Conn, boo bool, theip string, thetime time.Time, mytype int) {
	pp := 0
	conip := theip // already parsed client IP
	if boo {
		source.SetReadDeadline(time.Now().Add(3 * time.Second))
	}
	for {
		data := make([]byte, 1024)
		n, err := source.Read(data)
		if err != nil {
			fmt.Println(err)
			break
		}
		if boo {
			if pp < 4 {
				pp++
				fmt.Println(n, ": ", pp)
			}
			if pp == 3 {
				source.SetReadDeadline(time.Time{})
			}
			if pp == 1 && mytype == 4 && n > 1000 {
				// Example: remove IP from ipset if packet size is unexpected.
				exec.Command("ipset", "-D", "fivem", conip).Run()
				exec.Command("ipset", "-D", "fivembypass", conip).Run()
				fmt.Println("wrong p size con dropped")
				source.Close()
				destination.Close()
				return
			}
			// Additional packet checks (pp==2, pp==3) can be added as needed.
		}
		if _, err := destination.Write(data[:n]); err != nil {
			break
		}
	}
	fmt.Println("Connection closed by client")
	fmt.Println("Duration: ", time.Since(thetime))
	source.Close()
	destination.Close()
}

func handleTCPConnection(conn net.Conn, targetIP, targetPort, discordWebhook string) {
	defer conn.Close()
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Check if IP is banned.
	bannedIPsMu.RLock()
	if bannedIPs[clientIP] {
		bannedIPsMu.RUnlock()
		log.Printf(">> [TCP] Dropped connection from banned IP %s", clientIP)
		return
	}
	bannedIPsMu.RUnlock()

	// If already whitelisted, allow connection without handshake.
	if isWhitelisted(clientIP) {
		log.Printf(">> [TCP] [%s] Whitelisted - connection allowed", clientIP)
		proxyTCP(conn, targetIP, targetPort)
		return
	}

	// Minimal handshake check.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		log.Printf(">> [TCP] [%s] Error reading handshake: %v", clientIP, err)
		return
	}

	// Require either TLS or FiveM handshake.
	if !isTCPHandshake(buf[:n]) && !isFiveMHandshake(buf[:n]) {
		log.Printf(">> [TCP] [%s] Dropped - Invalid handshake", clientIP)
		return
	}

	// Successful handshake: whitelist the IP.
	updateWhitelist(clientIP)
	atomic.AddInt64(&tcpConnCount, 1)
	log.Printf(">> [TCP] [%s] Authenticated and whitelisted", clientIP)

	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] [%s] Backend connection error: %v", clientIP, err)
		return
	}
	// Enable keepalive.
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()

	// Send PROXY protocol header to forward original client IP.
	tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf(">> [TCP] [%s] Failed to assert client address type", clientIP)
		return
	}
	proxyHeader := fmt.Sprintf("PROXY TCP4 %s %s %d %s\r\n", clientIP, targetIP, tcpAddr.Port, targetPort)
	if _, err := backendConn.Write([]byte(proxyHeader)); err != nil {
		log.Printf(">> [TCP] [%s] Error writing PROXY header: %v", clientIP, err)
		return
	}
	// Forward the initial handshake data.
	if _, err := backendConn.Write(buf[:n]); err != nil {
		log.Printf(">> [TCP] [%s] Error writing handshake data: %v", clientIP, err)
		return
	}

	// Start forwarding data concurrently using the forward function.
	go forward(conn, backendConn, false, clientIP, time.Now(), 4)
	go forward(backendConn, conn, true, clientIP, time.Now(), 4)
}

func proxyTCP(client net.Conn, targetIP, targetPort string) {
	backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf(">> [TCP] Backend dial error: %v", err)
		return
	}
	if tcpConn, ok := backendConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
	defer backendConn.Close()
	// Use forward routines for data transfer.
	go forward(client, backendConn, false, client.RemoteAddr().String(), time.Now(), 4)
	go forward(backendConn, client, true, client.RemoteAddr().String(), time.Now(), 4)
}

// ------------------------
// UDP Proxy Logic (Persistent Sessions with Handshake Check)
// ------------------------

type sessionData struct {
	clientAddr  *net.UDPAddr // Client address.
	backendConn *net.UDPConn // Persistent connection to backend.
	lastActive  time.Time    // Last activity time.
	closeOnce   sync.Once
}

var (
	sessionMap = make(map[string]*sessionData)
	sessionMu  sync.Mutex
)

var (
	udpHandshakeChecked   = make(map[string]bool)
	udpHandshakeCheckedMu sync.Mutex
)

func hasCheckedHandshake(ip string) bool {
	udpHandshakeCheckedMu.Lock()
	defer udpHandshakeCheckedMu.Unlock()
	return udpHandshakeChecked[ip]
}

func markHandshakeChecked(ip string) {
	udpHandshakeCheckedMu.Lock()
	udpHandshakeChecked[ip] = true
	udpHandshakeCheckedMu.Unlock()
}

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

	go monitorDDoS(discordWebhook, "FiveGate", fmt.Sprintf("%s:%s", targetIP, listenPort), targetPort)

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listenConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf(">> [UDP] Read error: %v", err)
			continue
		}
		atomic.AddUint64(&ddosPacketCount, 1)
		atomic.AddUint64(&ddosByteCount, uint64(n))

		clientIP := clientAddr.IP.String()

		bannedIPsMu.RLock()
		if bannedIPs[clientIP] {
			bannedIPsMu.RUnlock()
			log.Printf(">> [UDP] Dropped packet from banned IP %s", clientIP)
			continue
		}
		bannedIPsMu.RUnlock()

		if !isWhitelisted(clientIP) && !hasCheckedHandshake(clientIP) {
			if !disableUDPHandshakeCheck {
				if !isFiveMHandshake(buf[:n]) {
					log.Printf(">> [UDP] [%s] Dropped - invalid handshake", clientIP)
					continue
				}
			}
			log.Printf(">> [UDP] [%s] Authenticated handshake (or bypassed) => whitelisted", clientIP)
			updateWhitelist(clientIP)
			markHandshakeChecked(clientIP)
		} else if !isWhitelisted(clientIP) {
			log.Printf(">> [UDP] [%s] No handshake pass", clientIP)
			continue
		}

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

		_, err = sd.backendConn.Write(buf[:n])
		if err != nil {
			log.Printf(">> [UDP] Write to backend error for client %s: %v", clientIP, err)
			continue
		}
	}
}

func handleUDPSession(listenConn *net.UDPConn, sd *sessionData) {
	buf := make([]byte, 2048)
	for {
		sd.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := sd.backendConn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf(">> [UDP] Error reading from backend for client %s: %v", sd.clientAddr, err)
			break
		}
		sessionMu.Lock()
		sd.lastActive = time.Now()
		sessionMu.Unlock()

		_, err = listenConn.WriteToUDP(buf[:n], sd.clientAddr)
		if err != nil {
			log.Printf(">> [UDP] Error writing to client %s: %v", sd.clientAddr, err)
		}
	}
}

// ------------------------
// DDoS Detection Logic
// ------------------------

func monitorDDoS(discordWebhook, serverName, serverIP, targetPort string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var peakPPS uint64
	var peakMbps float64
	var belowCount int

	const ppsThreshold = 1000
	const mbpsThreshold = 1.0

	for range ticker.C {
		pps := atomic.LoadUint64(&ddosPacketCount) / 10
		bytesCount := atomic.LoadUint64(&ddosByteCount)
		mbps := (float64(bytesCount)*8/1e6)/10

		if pps > peakPPS {
			peakPPS = pps
		}
		if mbps > peakMbps {
			peakMbps = mbps
		}
		atomic.StoreUint64(&ddosPacketCount, 0)
		atomic.StoreUint64(&ddosByteCount, 0)

		ddosMutex.Lock()
		if pps > ppsThreshold || mbps > mbpsThreshold {
			if !ddosAttackActive {
				sendDDoSAttackStarted(discordWebhook, serverName, serverIP,
					fmt.Sprintf(":zap: %d PPS | :electric_plug: %.2f Mbps", pps, mbps),
					"UDP Flood", targetPort)
				ddosAttackActive = true
			}
			belowCount = 0
		} else {
			if ddosAttackActive {
				belowCount++
				if belowCount >= 2 {
					sendDDoSAttackEnded(discordWebhook, serverName, serverIP,
						fmt.Sprintf(":zap: %d PPS | :electric_plug: %.2f Mbps", peakPPS, peakMbps),
						"Unique IPs: TBD, Banned IPs: TBD", "UDP Flood", targetPort)
					ddosAttackActive = false
					peakPPS = 0
					peakMbps = 0
					belowCount = 0
				}
			}
		}
		ddosMutex.Unlock()
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

	// Start TCP proxy.
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

	// Start UDproxy.
	go startUDPProxy(*listenPort, *targetIP, *targetPort, *discordWebhook)

	// Block forever.
	select {}
}

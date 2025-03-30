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
    "time"
)

// -------------------------------------------------------
// Discord embed support (unchanged from your original)
// -------------------------------------------------------

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

// -------------------------------------------------------
// Global variables
// -------------------------------------------------------

// Whitelisted IPs are always allowed through.
var whitelistedIPs = make(map[string]bool)
var whitelistedMu sync.RWMutex

// If you want to block obviously malicious IPs, you can store them here.
var bannedIPs = make(map[string]bool)
var bannedIPsMu sync.RWMutex

// -------------------------------------------------------
// Whitelisting logic
// -------------------------------------------------------

// isLikelyFiveMHandshake tries to detect a minimal “real” FiveM handshake.
// You can adjust these checks to suit your server’s actual handshake pattern.
func isLikelyFiveMHandshake(data string) bool {
    data = strings.ToLower(data)
    // Examples that might appear in a FiveM handshake:
    // "GET /info.json", "GET /players.json", "POST /client", or "fivem" strings, etc.
    if strings.Contains(data, "fivem") ||
       strings.Contains(data, "get /info.json") ||
       strings.Contains(data, "get /players.json") ||
       strings.Contains(data, "post /client") {
        return true
    }
    return false
}

// whitelistIP marks an IP as whitelisted. Once whitelisted, we don’t block or
// drop traffic from that IP.
func whitelistIP(ip string) {
    whitelistedMu.Lock()
    whitelistedIPs[ip] = true
    whitelistedMu.Unlock()
    log.Printf("[WHITELIST] IP %s is now whitelisted.", ip)
}

// isWhitelisted checks if an IP is whitelisted.
func isWhitelisted(ip string) bool {
    whitelistedMu.RLock()
    defer whitelistedMu.RUnlock()
    return whitelistedIPs[ip]
}

// isBanned checks if an IP is in the banned list.
func isBanned(ip string) bool {
    bannedIPsMu.RLock()
    defer bannedIPsMu.RUnlock()
    return bannedIPs[ip]
}

// banIP (optional) if you detect something blatantly malicious.
func banIP(ip string) {
    bannedIPsMu.Lock()
    bannedIPs[ip] = true
    bannedIPsMu.Unlock()
    log.Printf("[BAN] IP %s is banned.", ip)
}

// -------------------------------------------------------
// TCP Proxy
// -------------------------------------------------------

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
    clientAddr := client.RemoteAddr().String()
    clientIP := strings.Split(clientAddr, ":")[0]

    // Immediately drop if banned
    if isBanned(clientIP) {
        log.Printf("[TCP] Dropping banned IP %s", clientIP)
        client.Close()
        return
    }

    // If not whitelisted, read the first packet and see if it’s a legit handshake
    if !isWhitelisted(clientIP) {
        _ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
        buf := make([]byte, 2048)
        n, err := client.Read(buf)
        _ = client.SetReadDeadline(time.Time{})

        if err != nil && err != io.EOF {
            log.Printf("[TCP] Error reading handshake from %s: %v", clientAddr, err)
            client.Close()
            return
        }

        data := string(buf[:n])
        if !isLikelyFiveMHandshake(data) {
            // Not recognized => drop
            log.Printf("[TCP] Dropping unrecognized handshake from %s", clientAddr)
            client.Close()
            return
        }

        // Passed handshake => whitelist
        whitelistIP(clientIP)

        // We still need to forward that initial data to the backend
        // after we connect to it below.
        // (If you want to re-check or do something else, you can.)
        log.Printf("[TCP] Valid handshake from %s, forwarding...", clientAddr)

        // (No need to “ban” if it’s not recognized, we just drop.)
        // If you prefer, you could ban if the data is obviously malicious.
    }

    // Connect to the real backend
    backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
    if err != nil {
        log.Printf("[TCP] Error connecting to backend for %s: %v", clientAddr, err)
        client.Close()
        return
    }

    // If we read some data earlier (for handshake), forward it now.
    // We do that by reusing the buffer from above if needed. But that
    // code is simpler if we do it inline, so let's do it carefully:
    // Because we might have read data in the step above.
    // We'll do the "two-goroutine" copy pattern with a small fix:

    // The “multi-step” approach:
    // 1) If we read data for the handshake, keep it in a local buffer.
    // 2) Then start the piping of data from client to backend, and
    //    from backend to client.

    // Let’s keep a local copy of the handshake data:
    // Already done above in 'data' or 'buf'.

    // Start piping
    go func() {
        // If we had leftover handshake data, forward it first:
        // (But we only want to do this if we actually read some data
        // for the handshake. So we can keep the size in n.)
        if n > 0 {
            backend.Write(buf[:n])
        }
        // Now copy the rest from client to backend
        io.Copy(backend, client)
        backend.Close()
    }()

    go func() {
        io.Copy(client, backend)
        client.Close()
    }()

    log.Printf("[TCP] Connection from %s -> %s started", clientAddr, backend.RemoteAddr().String())
}

// startTCPProxy listens on listenPort and forwards to targetIP:targetPort
func startTCPProxy(listenPort, targetIP, targetPort string) {
    ln, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Fatalf("[TCP] Error starting TCP listener on port %s: %v", listenPort, err)
    }
    defer ln.Close()
    log.Printf("[TCP] Listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("[TCP] Error accepting connection: %v", err)
            continue
        }
        go handleTCPConnection(conn, targetIP, targetPort)
    }
}

// -------------------------------------------------------
// UDP Proxy
// -------------------------------------------------------

// We store a small struct for each client -> backend mapping.
type udpSession struct {
    backendConn *net.UDPConn
    lastSeen    time.Time
}

// For UDP, we do a “poor-man’s NAT” approach: each client IP:port
// is mapped to a single backend UDP connection. We forward data both ways.
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
    log.Printf("[UDP] Listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

    backendMap := make(map[string]*udpSession)
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

        // Immediately drop if banned
        if isBanned(clientIP) {
            log.Printf("[UDP] Dropping banned IP %s", clientIP)
            continue
        }

        // If not whitelisted, check handshake in this first packet
        if !isWhitelisted(clientIP) {
            payloadStr := strings.ToLower(string(buf[:n]))
            if !isLikelyFiveMHandshake(payloadStr) {
                // Not recognized => drop
                log.Printf("[UDP] Dropping unrecognized UDP from %s", clientKey)
                continue
            }
            // If recognized => whitelist
            whitelistIP(clientIP)
            log.Printf("[UDP] Whitelisted new client: %s", clientKey)
        }

        // At this point, we forward because the IP is whitelisted
        mu.Lock()
        session, found := backendMap[clientKey]
        if !found {
            // Create a new UDP connection to the backend
            targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
            if err != nil {
                log.Printf("[UDP] Error resolving backend address: %v", err)
                mu.Unlock()
                continue
            }
            backendConn, err := net.DialUDP("udp", nil, targetAddr)
            if err != nil {
                log.Printf("[UDP] Error dialing backend for %s: %v", clientKey, err)
                mu.Unlock()
                continue
            }
            session = &udpSession{
                backendConn: backendConn,
                lastSeen:    time.Now(),
            }
            backendMap[clientKey] = session

            // Start a goroutine to read from the backend and forward to the client
            go func(client *net.UDPAddr, bc *net.UDPConn, key string) {
                bBuf := make([]byte, 2048)
                for {
                    bc.SetReadDeadline(time.Now().Add(5 * time.Minute))
                    n2, _, err2 := bc.ReadFromUDP(bBuf)
                    if err2 != nil {
                        log.Printf("[UDP] Closing session for %s: %v", key, err2)
                        bc.Close()
                        mu.Lock()
                        delete(backendMap, key)
                        mu.Unlock()
                        return
                    }
                    // Forward back to the client
                    conn.WriteToUDP(bBuf[:n2], client)
                }
            }(clientAddr, session.backendConn, clientKey)
        }
        session.lastSeen = time.Now()
        // Forward the packet to the backend
        session.backendConn.Write(buf[:n])
        mu.Unlock()
    }
}

// -------------------------------------------------------
// main()
// -------------------------------------------------------

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

    // If you want to send an initial Discord message that the proxy started:
    sendDiscordEmbed(*discordWebhook, "Proxy Started",
        fmt.Sprintf("Listening on %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort),
        0x00ff00)

    // Start TCP in the background
    go startTCPProxy(*listenPort, *targetIP, *targetPort)

    // Start UDP (blocking call)
    startUDPProxy(*listenPort, *targetIP, *targetPort)
}

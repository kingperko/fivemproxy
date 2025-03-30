package main

import (
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

// Simple IP allow/block
var whitelistedIPs = make(map[string]bool)
var whitelistedMu sync.RWMutex

func isWhitelisted(ip string) bool {
    whitelistedMu.RLock()
    defer whitelistedMu.RUnlock()
    return whitelistedIPs[ip]
}

func whitelistIP(ip string) {
    whitelistedMu.Lock()
    whitelistedIPs[ip] = true
    whitelistedMu.Unlock()
    log.Printf("[WHITELIST] %s", ip)
}

// Example check for a "FiveM handshake"
func isLikelyFiveMHandshake(data string) bool {
    data = strings.ToLower(data)
    return strings.Contains(data, "fivem") ||
        strings.Contains(data, "get /info.json") ||
        strings.Contains(data, "get /players.json") ||
        strings.Contains(data, "post /client")
}

func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
    defer client.Close()

    clientAddr := client.RemoteAddr().String()
    clientIP := strings.Split(clientAddr, ":")[0]

    // If not whitelisted, check the first packet for a legit handshake.
    if !isWhitelisted(clientIP) {
        // Make a buffer to read the first data from the client.
        buf := make([]byte, 2048)

        // Try to read within 3 seconds (avoid hanging on junk).
        _ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
        n, err := client.Read(buf)
        _ = client.SetReadDeadline(time.Time{})

        if err != nil && err != io.EOF {
            log.Printf("[TCP] Error reading handshake from %s: %v", clientAddr, err)
            return
        }
        // If we actually read something, check if it's a valid handshake:
        if n > 0 {
            data := string(buf[:n])
            if !isLikelyFiveMHandshake(data) {
                log.Printf("[TCP] Dropping unrecognized handshake from %s", clientAddr)
                return
            }
            // Valid => whitelist
            whitelistIP(clientIP)
            log.Printf("[TCP] Valid handshake from %s", clientAddr)
        }
        // If n == 0, we read nothing; that’s also suspicious, so we can drop.
        if n == 0 {
            log.Printf("[TCP] Empty handshake from %s, dropping.", clientAddr)
            return
        }

        // Now connect to the backend and forward that first packet.
        backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
        if err != nil {
            log.Printf("[TCP] Backend dial error: %v", err)
            return
        }
        defer backend.Close()

        // Forward the handshake data we just read:
        _, _ = backend.Write(buf[:n])

        // Start piping the rest of the traffic in goroutines:
        go io.Copy(backend, client)
        io.Copy(client, backend)
        return
    }

    // If IP is already whitelisted, just do a normal TCP proxy (no handshake check).
    backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
    if err != nil {
        log.Printf("[TCP] Backend dial error: %v", err)
        return
    }
    defer backend.Close()

    go io.Copy(backend, client)
    io.Copy(client, backend)
}

func startTCPProxy(listenPort, targetIP, targetPort string) {
    ln, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Fatalf("[TCP] Listen error on port %s: %v", listenPort, err)
    }
    defer ln.Close()
    log.Printf("[TCP] Listening on %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("[TCP] Accept error: %v", err)
            continue
        }
        go handleTCPConnection(conn, targetIP, targetPort)
    }
}

// Minimal main
func main() {
    targetIP := flag.String("targetIP", "", "Backend IP")
    targetPort := flag.String("targetPort", "", "Backend Port")
    listenPort := flag.String("listenPort", "", "Proxy Listen Port")
    flag.Parse()

    if *targetIP == "" || *targetPort == "" || *listenPort == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<ip> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
        os.Exit(1)
    }

    go startTCPProxy(*listenPort, *targetIP, *targetPort)
    // If you also have a UDP proxy, start it here in a similar manner.
    select {} // block forever
}

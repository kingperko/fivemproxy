// main.go
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

// Simple IP allow/block management.
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

// Example check for a "FiveM handshake" in the initial data.
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

    // If not whitelisted, perform a handshake check.
    if !isWhitelisted(clientIP) {
        buf := make([]byte, 2048)
        client.SetReadDeadline(time.Now().Add(3 * time.Second))
        n, err := client.Read(buf)
        client.SetReadDeadline(time.Time{})
        if err != nil && err != io.EOF {
            log.Printf("[TCP] Error reading handshake from %s: %v", clientAddr, err)
            return
        }
        if n > 0 {
            data := string(buf[:n])
            if !isLikelyFiveMHandshake(data) {
                log.Printf("[TCP] Dropping unrecognized handshake from %s", clientAddr)
                return
            }
            // Valid handshake: whitelist IP.
            whitelistIP(clientIP)
            log.Printf("[TCP] Valid handshake from %s", clientAddr)

           	// Connect to backend and forward the handshake data.
            backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
            if err != nil {
                log.Printf("[TCP] Backend dial error: %v", err)
                return
            }
            defer backend.Close()

            _, _ = backend.Write(buf[:n])
            go io.Copy(backend, client)
           	io.Copy(client, backend)
            return
        }
        if n == 0 {
            log.Printf("[TCP] Empty handshake from %s, dropping.", clientAddr)
            return
        }
    }

    // If already whitelisted, just forward traffic.
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

// Minimal main function.
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

    // Block forever (or add UDP proxy here if needed)
    select {}
}

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

// We'll reuse some helpers from the original code.
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// ------------------- TCP Proxy -------------------

// handleTCPConnection forwards data between one TCP client and the backend server.
func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
    startTime := time.Now()
    clientIP := strings.Split(client.RemoteAddr().String(), ":")[0]
    log.Printf("TCP: Accepted connection from %s", clientIP)
    defer client.Close()

    // Connect to backend server for TCP.
    backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
    if err != nil {
        log.Printf("TCP: Error connecting to backend for %s: %v", clientIP, err)
        return
    }
    defer backend.Close()

    // Read an initial packet for logging (not strictly required).
    client.SetReadDeadline(time.Now().Add(3 * time.Second))
    buf := make([]byte, 1024)
    n, err := client.Read(buf)
    client.SetReadDeadline(time.Time{}) // Remove the deadline.

    if err == nil && n > 0 {
        initialData := string(buf[:n])
        log.Printf("TCP: Initial packet from %s: %q", clientIP, initialData[:min(n, 64)])
        // Forward that data to the backend.
        _, _ = backend.Write(buf[:n])
    } else if err != nil && err != io.EOF {
        log.Printf("TCP: Error reading initial data from %s: %v", clientIP, err)
        return
    }

    // Bidirectional copy (client <-> backend).
    done := make(chan struct{}, 2)
    go func() {
        io.Copy(backend, client)
        done <- struct{}{}
    }()
    go func() {
        io.Copy(client, backend)
        done <- struct{}{}
    }()

    // Wait until one side closes.
    <-done
    log.Printf("TCP: Connection from %s closed after %v", clientIP, time.Since(startTime))
}

// startTCPProxy listens on listenPort (TCP) and forwards to targetIP:targetPort.
func startTCPProxy(listenPort, targetIP, targetPort string) {
    ln, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Fatalf("Error starting TCP listener on port %s: %v", listenPort, err)
    }
    defer ln.Close()

    log.Printf("TCP proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("TCP: Error accepting connection: %v", err)
            continue
        }
        go handleTCPConnection(conn, targetIP, targetPort)
    }
}

// ------------------- UDP Proxy (Naive NAT) -------------------

// We track each client IP:port => a dedicated UDP connection to the backend.
type udpMapEntry struct {
    backendConn *net.UDPConn
    lastSeen    time.Time
}

// handleUDPProxy listens on listenPort (UDP) and forwards data to targetIP:targetPort.
// Each unique client IP:port gets its own backend UDP connection.
func startUDPProxy(listenPort, targetIP, targetPort string) {
    // Resolve the address we'll listen on for UDP.
    addr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
    if err != nil {
        log.Fatalf("UDP: Error resolving UDP addr: %v", err)
    }

    // Listen for incoming UDP packets.
    conn, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalf("UDP: Error listening on port %s: %v", listenPort, err)
    }
    defer conn.Close()

    log.Printf("UDP proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

    // We'll store client => backendConn in a map, so multiple clients can connect.
    var (
        backendMap = make(map[string]*udpMapEntry)
        mu         sync.Mutex
    )

    buf := make([]byte, 2048)

    for {
        n, clientAddr, err := conn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("UDP: Error reading: %v", err)
            continue
        }

        clientKey := clientAddr.String()

        mu.Lock()
        entry, found := backendMap[clientKey]
        if !found {
            // Create a new backend connection for this client.
            targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
            if err != nil {
                log.Printf("UDP: Error resolving backend address: %v", err)
                mu.Unlock()
                continue
            }
            bc, err := net.DialUDP("udp", nil, targetAddr)
            if err != nil {
                log.Printf("UDP: Error dialing backend for %s: %v", clientKey, err)
                mu.Unlock()
                continue
            }

            entry = &udpMapEntry{
                backendConn: bc,
                lastSeen:    time.Now(),
            }
            backendMap[clientKey] = entry

            // Start a goroutine to read from the backend and forward to the client.
            go func(client *net.UDPAddr, backendConn *net.UDPConn) {
                bBuf := make([]byte, 2048)
                for {
                    backendConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
                    n2, _, err2 := backendConn.ReadFromUDP(bBuf)
                    if err2 != nil {
                        // Usually means the backendConn closed or timed out.
                        log.Printf("UDP: Closing connection for %s: %v", client.String(), err2)
                        backendConn.Close()
                        mu.Lock()
                        delete(backendMap, client.String())
                        mu.Unlock()
                        return
                    }
                    // Forward data back to the client.
                    conn.WriteToUDP(bBuf[:n2], client)
                }
            }(clientAddr, bc)
        }
        // Update lastSeen and forward the data to the backend.
        entry.lastSeen = time.Now()
        _, _ = entry.backendConn.Write(buf[:n])
        mu.Unlock()
    }
}

// ------------------- main -------------------

func main() {
    targetIP := flag.String("targetIP", "", "Backend server IP address")
    targetPort := flag.String("targetPort", "", "Backend server port")
    listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
    flag.Parse()

    if *targetIP == "" || *targetPort == "" || *listenPort == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
        os.Exit(1)
    }

    // Start both TCP and UDP proxies on the same port.
    go startTCPProxy(*listenPort, *targetIP, *targetPort)
    startUDPProxy(*listenPort, *targetIP, *targetPort)
}

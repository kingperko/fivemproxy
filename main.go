package main

import (
    "errors"
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

// sendProxyHeader writes a PROXY protocol v1 header to the backend connection.
// Format: "PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n"
func sendProxyHeader(clientAddr net.Addr, targetIP, targetPort string, backend net.Conn) error {
    tcpAddr, ok := clientAddr.(*net.TCPAddr)
    if !ok {
        return errors.New("client address is not a TCPAddr")
    }
    // If it's IPv6, you'd do "TCP6" instead, but here we assume IPv4.
    header := fmt.Sprintf("PROXY TCP4 %s %s %d %s\r\n",
        tcpAddr.IP.String(), targetIP, tcpAddr.Port, targetPort)
    _, err := backend.Write([]byte(header))
    return err
}

// handleTCPConnection proxies a new TCP client connection to the backend.
// It first sends a PROXY protocol header to preserve the real client IP.
func handleTCPConnection(clientConn net.Conn, targetIP, targetPort string) {
    defer clientConn.Close()
    clientAddr := clientConn.RemoteAddr().String()
    log.Printf("[TCP] Client connected: %s", clientAddr)

    // Dial the backend
    backendConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
    if err != nil {
        log.Printf("[TCP] Failed to connect to backend %s:%s: %v", targetIP, targetPort, err)
        return
    }
    defer backendConn.Close()

    // Send PROXY protocol v1 header
    if err := sendProxyHeader(clientConn.RemoteAddr(), targetIP, targetPort, backendConn); err != nil {
        log.Printf("[TCP] Error sending PROXY header for %s: %v", clientAddr, err)
        return
    }

    // Now do bidirectional copy
    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        _, _ = io.Copy(backendConn, clientConn)
        backendConn.Close()
    }()
    go func() {
        defer wg.Done()
        _, _ = io.Copy(clientConn, backendConn)
        clientConn.Close()
    }()

    wg.Wait()
    log.Printf("[TCP] Connection closed: %s", clientAddr)
}

// startTCPListener starts a TCP listener on listenPort and forwards to targetIP:targetPort.
func startTCPListener(listenPort, targetIP, targetPort string) {
    ln, err := net.Listen("tcp", ":"+listenPort)
    if err != nil {
        log.Fatalf("[TCP] Failed to listen on port %s: %v", listenPort, err)
    }
    defer ln.Close()
    log.Printf("[TCP] Listening on port %s -> %s:%s", listenPort, targetIP, targetPort)

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Printf("[TCP] Accept error: %v", err)
            continue
        }
        go handleTCPConnection(conn, targetIP, targetPort)
    }
}

// ---------------------
// Raw UDP Forwarding
// ---------------------

// For each client IP:port, we create a “session” to the backend so we can forward traffic both ways.
type udpSession struct {
    clientAddr  *net.UDPAddr
    backendConn *net.UDPConn
    lastActive  time.Time
}

var (
    sessionMap = make(map[string]*udpSession)
    sessionMu  sync.Mutex
)

// handleUDPSession reads from the backend and sends to the client.
func handleUDPSession(listenConn *net.UDPConn, sess *udpSession, clientKey string) {
    buf := make([]byte, 65535)
    idleTimeout := 60 * time.Second

    for {
        // If no data from backend for 30s, check if idle
        sess.backendConn.SetReadDeadline(time.Now().Add(30 * time.Second))
        n, err := sess.backendConn.Read(buf)
        if err != nil {
            // If it's a timeout, check idle
            if ne, ok := err.(net.Error); ok && ne.Timeout() {
                sessionMu.Lock()
                if time.Since(sess.lastActive) > idleTimeout {
                    // Remove session
                    delete(sessionMap, clientKey)
                    sessionMu.Unlock()
                    log.Printf("[UDP] Session to %s timed out, closing", clientKey)
                    return
                }
                sessionMu.Unlock()
                continue
            }
            // Real error
            log.Printf("[UDP] Backend read error for %s: %v", clientKey, err)
            break
        }

        sessionMu.Lock()
        sess.lastActive = time.Now()
        sessionMu.Unlock()

        // Forward data to client
        _, werr := listenConn.WriteToUDP(buf[:n], sess.clientAddr)
        if werr != nil {
            log.Printf("[UDP] Error writing to client %s: %v", clientKey, werr)
            break
        }
    }

    sessionMu.Lock()
    delete(sessionMap, clientKey)
    sessionMu.Unlock()
    _ = sess.backendConn.Close()
}

// startUDPListener starts a raw UDP forwarder on listenPort -> targetIP:targetPort.
// The server will see the traffic as coming from the proxy’s IP unless you add
// a custom protocol or run TProxy at the kernel level.
func startUDPListener(listenPort, targetIP, targetPort string) {
    listenAddr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
    if err != nil {
        log.Fatalf("[UDP] Resolve error: %v", err)
    }
    listenConn, err := net.ListenUDP("udp", listenAddr)
    if err != nil {
        log.Fatalf("[UDP] Failed to listen on UDP port %s: %v", listenPort, err)
    }
    log.Printf("[UDP] Listening on port %s -> %s:%s", listenPort, targetIP, targetPort)

    backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
    if err != nil {
        log.Fatalf("[UDP] Failed to resolve backend %s:%s: %v", targetIP, targetPort, err)
    }

    buf := make([]byte, 65535)
    for {
        n, clientAddr, err := listenConn.ReadFromUDP(buf)
        if err != nil {
            continue
        }

        clientKey := clientAddr.String()

        sessionMu.Lock()
        sess, exists := sessionMap[clientKey]
        if !exists {
            backendConn, berr := net.DialUDP("udp", nil, backendAddr)
            if berr != nil {
                sessionMu.Unlock()
                log.Printf("[UDP] Dial backend error for %s: %v", clientKey, berr)
                continue
            }
            sess = &udpSession{
                clientAddr:  clientAddr,
                backendConn: backendConn,
                lastActive:  time.Now(),
            }
            sessionMap[clientKey] = sess
            go handleUDPSession(listenConn, sess, clientKey)
        } else {
            sess.lastActive = time.Now()
        }
        sessionMu.Unlock()

        // Forward the data to the backend
        _, werr := sess.backendConn.Write(buf[:n])
        if werr != nil {
            log.Printf("[UDP] Write to backend error for %s: %v", clientKey, werr)
            continue
        }
    }
}

// ---------------------
// Main
// ---------------------

func main() {
    targetIP := flag.String("targetIP", "", "Backend server IP")
    targetPort := flag.String("targetPort", "", "Backend server port")
    listenPort := flag.String("listenPort", "", "Local port to listen on for TCP and UDP")
    flag.Parse()

    if *targetIP == "" || *targetPort == "" || *listenPort == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
        os.Exit(1)
    }

    // Start TCP and UDP in parallel
    go startTCPListener(*listenPort, *targetIP, *targetPort)
    go startUDPListener(*listenPort, *targetIP, *targetPort)

    log.Printf("[INFO] Proxy forwarding to %s:%s on TCP/UDP port %s", *targetIP, *targetPort, *listenPort)
    select {}
}

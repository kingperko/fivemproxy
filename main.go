package main

import (
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "sync"
    "time"
)

const (
    bufferSize = 65535
    // clientTimeout = 2 * time.Minute  // Removed usage to avoid forced timeouts
)

var discordWebhook string

type UDPProxy struct {
    clientConn  *net.UDPConn
    serverAddr  *net.UDPAddr
    connections sync.Map
}

type UDPConnection struct {
    serverConn *net.UDPConn
    lastActive time.Time
}

func NewUDPProxy(localAddr, serverAddr string) (*UDPProxy, error) {
    clientUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve local UDP addr %s: %w", localAddr, err)
    }

    clientConn, err := net.ListenUDP("udp", clientUDPAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to listen on %s: %w", localAddr, err)
    }

    serverUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve server UDP addr %s: %w", serverAddr, err)
    }

    return &UDPProxy{
        clientConn: clientConn,
        serverAddr: serverUDPAddr,
    }, nil
}

func (p *UDPProxy) handleClient(clientAddr *net.UDPAddr, data []byte) {
    conn, loaded := p.connections.Load(clientAddr.String())
    if !loaded {
        serverConn, err := net.DialUDP("udp", nil, p.serverAddr)
        if err != nil {
            log.Printf("[UDP] Error connecting to backend: %v\n", err)
            return
        }

        newConn := &UDPConnection{
            serverConn: serverConn,
            lastActive: time.Now(),
        }
        p.connections.Store(clientAddr.String(), newConn)

        // Start reading from the server for this client
        go p.listenServer(clientAddr, newConn)
        log.Printf("[UDP] New connection from %s\n", clientAddr.String())

        conn = newConn
    }

    udpConn := conn.(*UDPConnection)
    udpConn.lastActive = time.Now()

    // Forward data from the client to the server
    _, err := udpConn.serverConn.Write(data)
    if err != nil {
        log.Printf("[UDP] Failed to write to server for %s: %v\n", clientAddr.String(), err)
    }
}

func (p *UDPProxy) listenServer(clientAddr *net.UDPAddr, conn *UDPConnection) {
    buf := make([]byte, bufferSize)

    for {
        // **No** SetReadDeadline call here—no forced timeout
        n, err := conn.serverConn.Read(buf)
        if err != nil {
            log.Printf("[UDP] Read error from server for %s: %v\n", clientAddr.String(), err)
            p.connections.Delete(clientAddr.String())
            conn.serverConn.Close()
            return
        }

        // Forward server data back to the client
        _, werr := p.clientConn.WriteToUDP(buf[:n], clientAddr)
        if werr != nil {
            log.Printf("[UDP] Failed to write to client %s: %v\n", clientAddr.String(), werr)
        }
    }
}

func (p *UDPProxy) Start() {
    log.Printf("[UDP] Proxy listening on %s\n", p.clientConn.LocalAddr().String())
    buffer := make([]byte, bufferSize)

    for {
        n, clientAddr, err := p.clientConn.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("[UDP] ReadFromUDP error: %v\n", err)
            continue
        }
        go p.handleClient(clientAddr, buffer[:n])
    }
}

// TCP proxy logic
func handleTCPConnection(client net.Conn, serverAddr string) {
    defer client.Close()
    log.Printf("[TCP] New connection from %s\n", client.RemoteAddr().String())

    server, err := net.Dial("tcp", serverAddr)
    if err != nil {
        log.Printf("[TCP] Backend dial error: %v\n", err)
        return
    }
    defer server.Close()

    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        io.Copy(server, client)
    }()
    go func() {
        defer wg.Done()
        io.Copy(client, server)
    }()
    wg.Wait()

    log.Printf("[TCP] Connection closed for %s\n", client.RemoteAddr().String())
}

func startTCPProxy(localAddr, serverAddr string) {
    listener, err := net.Listen("tcp", localAddr)
    if err != nil {
        log.Fatalf("[TCP] Listen error on %s: %v", localAddr, err)
    }
    defer listener.Close()

    log.Printf("[TCP] Proxy listening on %s\n", listener.Addr().String())

    for {
        client, err := listener.Accept()
        if err != nil {
            log.Printf("[TCP] Accept error: %v\n", err)
            continue
        }
        go handleTCPConnection(client, serverAddr)
    }
}

func main() {
    listenHost := flag.String("listenHost", "0.0.0.0", "Local IP to bind")
    listenPort := flag.String("listenPort", "", "Local port to listen on for TCP/UDP")
    targetIP := flag.String("targetIP", "", "Backend server IP")
    targetPort := flag.String("targetPort", "", "Backend server port")
    flag.StringVar(&discordWebhook, "discordWebhook", "", "Discord webhook URL for alerts (optional)")
    flag.Parse()

    if *targetIP == "" || *targetPort == "" || *listenPort == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenHost=<IP> -listenPort=<port>\n", os.Args[0])
        os.Exit(1)
    }

    localAddr := net.JoinHostPort(*listenHost, *listenPort)
    serverAddr := net.JoinHostPort(*targetIP, *targetPort)

    // Start the UDP proxy
    udpProxy, err := NewUDPProxy(localAddr, serverAddr)
    if err != nil {
        log.Fatalf("[UDP] Failed to start proxy on %s: %v", localAddr, err)
    }
    go udpProxy.Start()

    // Start the TCP proxy
    startTCPProxy(localAddr, serverAddr)
}

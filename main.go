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
    // No forced timeouts in this version
)

// Optional: if you want to send logs or alerts to a Discord webhook, you can use this variable.
var discordWebhook string

// UDPProxy tracks our listening socket (clientConn) and the backend serverAddr.
// We also store a map of each client's address to its “connection” (which is basically
// a DialUDP socket to the real server).
type UDPProxy struct {
    clientConn  *net.UDPConn      // The UDP socket that listens for incoming client traffic
    serverAddr  *net.UDPAddr      // The real server’s IP:port we forward to
    connections sync.Map          // map[string]*UDPConnection  (key = clientAddr.String())
}

// UDPConnection represents a single client’s UDP session with the backend server.
type UDPConnection struct {
    serverConn *net.UDPConn
    lastActive time.Time
}

// NewUDPProxy sets up a UDP listener on localAddr (e.g. `0.0.0.0:30120`) and
// prepares to forward traffic to serverAddr (e.g. `real.fivem.server:30120`).
func NewUDPProxy(localAddr, serverAddr string) (*UDPProxy, error) {
    // Listen for incoming UDP
    clientUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve local UDP addr %s: %w", localAddr, err)
    }
    clientConn, err := net.ListenUDP("udp", clientUDPAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to listen on %s: %w", localAddr, err)
    }

    // Resolve the real server’s UDP address
    serverUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr)
    if err != nil {
        return nil, fmt.Errorf("failed to resolve server UDP addr %s: %w", serverAddr, err)
    }

    return &UDPProxy{
        clientConn: clientConn,
        serverAddr: serverUDPAddr,
    }, nil
}

// handleClient either finds or creates a serverConn for this client, then
// forwards the incoming data to the server.
func (p *UDPProxy) handleClient(clientAddr *net.UDPAddr, data []byte) {
    // Check if we already have a connection for this client
    conn, loaded := p.connections.Load(clientAddr.String())
    if !loaded {
        // Create a brand-new connection to the real server
        serverConn, err := net.DialUDP("udp", nil, p.serverAddr)
        if err != nil {
            log.Printf("[UDP] Error connecting to backend for %s: %v\n", clientAddr, err)
            return
        }

        // Track the new connection
        newConn := &UDPConnection{
            serverConn: serverConn,
            lastActive: time.Now(),
        }
        p.connections.Store(clientAddr.String(), newConn)

        // Start reading from the server for this client
        go p.listenServer(clientAddr, newConn)
        log.Printf("[UDP] New client %s -> server %s\n",
            clientAddr.String(), p.serverAddr.String())

        conn = newConn
    }

    // Update lastActive and forward the data to the server
    udpConn := conn.(*UDPConnection)
    udpConn.lastActive = time.Now()
    _, err := udpConn.serverConn.Write(data)
    if err != nil {
        log.Printf("[UDP] Write to server failed for %s: %v\n", clientAddr.String(), err)
    }
}

// listenServer continuously reads from the serverConn and forwards that data
// back to the client address. We do **not** use timeouts, so this stays alive
// until a real read/write error occurs.
func (p *UDPProxy) listenServer(clientAddr *net.UDPAddr, conn *UDPConnection) {
    buf := make([]byte, bufferSize)
    for {
        // No read deadline -> no forced timeout
        n, err := conn.serverConn.Read(buf)
        if err != nil {
            // Some real error occurred (connection reset, etc.)
            log.Printf("[UDP] Server read error for client %s: %v\n", clientAddr.String(), err)
            // Cleanup
            p.connections.Delete(clientAddr.String())
            conn.serverConn.Close()
            return
        }

        // Forward server data back to the client
        _, werr := p.clientConn.WriteToUDP(buf[:n], clientAddr)
        if werr != nil {
            log.Printf("[UDP] Write to client %s failed: %v\n", clientAddr.String(), werr)
        }
    }
}

// Start runs the main loop that receives UDP packets from clients and passes them off.
func (p *UDPProxy) Start() {
    log.Printf("[UDP] Proxy listening on %s, forwarding to %s\n",
        p.clientConn.LocalAddr().String(), p.serverAddr.String())

    buf := make([]byte, bufferSize)
    for {
        n, clientAddr, err := p.clientConn.ReadFromUDP(buf)
        if err != nil {
            log.Printf("[UDP] ReadFromUDP error: %v\n", err)
            continue
        }
        go p.handleClient(clientAddr, buf[:n])
    }
}

// handleTCPConnection is a simple TCP forwarder that copies data back and forth.
func handleTCPConnection(client net.Conn, serverAddr string) {
    defer client.Close()
    log.Printf("[TCP] New client: %s\n", client.RemoteAddr().String())

    server, err := net.Dial("tcp", serverAddr)
    if err != nil {
        log.Printf("[TCP] Dial to server %s failed: %v\n", serverAddr, err)
        return
    }
    defer server.Close()

    var wg sync.WaitGroup
    wg.Add(2)

    // client -> server
    go func() {
        defer wg.Done()
        io.Copy(server, client)
    }()
    // server -> client
    go func() {
        defer wg.Done()
        io.Copy(client, server)
    }()
    wg.Wait()

    log.Printf("[TCP] Connection closed for %s\n", client.RemoteAddr().String())
}

// startTCPProxy listens on localAddr for incoming TCP connections
// and forwards them to serverAddr.
func startTCPProxy(localAddr, serverAddr string) {
    listener, err := net.Listen("tcp", localAddr)
    if err != nil {
        log.Fatalf("[TCP] Listen error on %s: %v", localAddr, err)
    }
    defer listener.Close()

    log.Printf("[TCP] Proxy listening on %s, forwarding to %s\n",
        listener.Addr().String(), serverAddr)

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
    listenHost := flag.String("listenHost", "0.0.0.0", "Local IP to bind for proxy")
    listenPort := flag.String("listenPort", "", "Local port to listen on (TCP+UDP)")
    targetIP := flag.String("targetIP", "", "Real backend server IP")
    targetPort := flag.String("targetPort", "", "Real backend server port")
    flag.StringVar(&discordWebhook, "discordWebhook", "", "Discord webhook URL for alerts (optional)")
    flag.Parse()

    if *listenPort == "" || *targetIP == "" || *targetPort == "" {
        fmt.Fprintf(os.Stderr, "Usage: %s -listenHost=0.0.0.0 -listenPort=30120 -targetIP=x.x.x.x -targetPort=30120\n", os.Args[0])
        os.Exit(1)
    }

    localAddr := net.JoinHostPort(*listenHost, *listenPort)
    serverAddr := net.JoinHostPort(*targetIP, *targetPort)

    // Start UDP Proxy
    udpProxy, err := NewUDPProxy(localAddr, serverAddr)
    if err != nil {
        log.Fatalf("[UDP] Failed to start UDP proxy on %s: %v", localAddr, err)
    }
    go udpProxy.Start()

    // Start TCP Proxy
    startTCPProxy(localAddr, serverAddr)
}

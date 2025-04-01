package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	bufferSize = 65535
	// This implementation does not use forced timeouts to maintain persistent connections.
)

var discordWebhook string

// UDPProxy handles UDP traffic by listening on a given address and forwarding packets to the backend.
type UDPProxy struct {
	clientConn  *net.UDPConn      // UDP socket for incoming client packets.
	serverAddr  *net.UDPAddr      // Backend server's UDP address.
	connections sync.Map          // Maps client address string to *UDPConnection.
}

// UDPConnection holds a connection to the backend for a specific client.
type UDPConnection struct {
	serverConn *net.UDPConn // The UDP connection from proxy to backend.
	// lastActive is available for potential cleanup but is not used here.
}

// NewUDPProxy creates and returns a UDPProxy listening on localAddr and forwarding to serverAddr.
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

// handleClient forwards data received from a client to the backend server.
// If a connection for this client does not exist, it creates one.
func (p *UDPProxy) handleClient(clientAddr *net.UDPAddr, data []byte) {
	conn, loaded := p.connections.Load(clientAddr.String())
	if !loaded {
		// Create a new connection to the backend server.
		serverConn, err := net.DialUDP("udp", nil, p.serverAddr)
		if err != nil {
			log.Printf("[UDP] Error connecting to backend for %s: %v\n", clientAddr, err)
			return
		}
		newConn := &UDPConnection{
			serverConn: serverConn,
		}
		p.connections.Store(clientAddr.String(), newConn)
		go p.listenServer(clientAddr, newConn)
		log.Printf("[UDP] New client %s proxied to %s\n", clientAddr.String(), p.serverAddr.String())
		conn = newConn
	}
	udpConn := conn.(*UDPConnection)
	_, err := udpConn.serverConn.Write(data)
	if err != nil {
		log.Printf("[UDP] Error writing to backend for %s: %v\n", clientAddr.String(), err)
	}
}

// listenServer continuously reads from the backend server for a given client
// and forwards any received packets back to that client.
func (p *UDPProxy) listenServer(clientAddr *net.UDPAddr, conn *UDPConnection) {
	buf := make([]byte, bufferSize)
	for {
		n, err := conn.serverConn.Read(buf)
		if err != nil {
			log.Printf("[UDP] Error reading from backend for client %s: %v\n", clientAddr.String(), err)
			p.connections.Delete(clientAddr.String())
			conn.serverConn.Close()
			return
		}
		_, werr := p.clientConn.WriteToUDP(buf[:n], clientAddr)
		if werr != nil {
			log.Printf("[UDP] Error writing to client %s: %v\n", clientAddr.String(), werr)
		}
	}
}

// Start begins the UDP proxy loop.
func (p *UDPProxy) Start() {
	log.Printf("[UDP] Proxy listening on %s and forwarding to %s\n", p.clientConn.LocalAddr().String(), p.serverAddr.String())
	buf := make([]byte, bufferSize)
	for {
		n, clientAddr, err := p.clientConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP] Error reading from UDP: %v\n", err)
			continue
		}
		go p.handleClient(clientAddr, buf[:n])
	}
}

// handleTCPConnection creates a TCP connection between the client and backend,
// copying data in both directions.
func handleTCPConnection(client net.Conn, serverAddr string) {
	defer client.Close()
	log.Printf("[TCP] New connection from %s\n", client.RemoteAddr().String())
	server, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("[TCP] Error connecting to backend at %s: %v\n", serverAddr, err)
		return
	}
	defer server.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	// Client → Server
	go func() {
		defer wg.Done()
		io.Copy(server, client)
	}()
	// Server → Client
	go func() {
		defer wg.Done()
		io.Copy(client, server)
	}()
	wg.Wait()
	log.Printf("[TCP] Closed connection from %s\n", client.RemoteAddr().String())
}

// startTCPProxy listens for TCP connections on localAddr and proxies them to the backend.
func startTCPProxy(localAddr, serverAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("[TCP] Error listening on %s: %v", localAddr, err)
	}
	defer listener.Close()
	log.Printf("[TCP] Proxy listening on %s and forwarding to %s\n", listener.Addr().String(), serverAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("[TCP] Error accepting connection: %v\n", err)
			continue
		}
		go handleTCPConnection(client, serverAddr)
	}
}

func main() {
	// Command-line flags.
	listenHost := flag.String("listenHost", "0.0.0.0", "Local IP to bind for proxy (as assigned by Pterodactyl)")
	listenPort := flag.String("listenPort", "", "Local port to listen on for TCP and UDP (as assigned by Pterodactyl)")
	targetIP := flag.String("targetIP", "", "Backend (real) FiveM server IP")
	targetPort := flag.String("targetPort", "", "Backend (real) FiveM server port")
	flag.StringVar(&discordWebhook, "discordWebhook", "", "Discord webhook URL for alerts (optional)")
	flag.Parse()

	if *listenPort == "" || *targetIP == "" || *targetPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -listenHost=0.0.0.0 -listenPort=<port> -targetIP=<backend IP> -targetPort=<backend port>\n", os.Args[0])
		os.Exit(1)
	}

	localAddr := net.JoinHostPort(*listenHost, *listenPort)
	serverAddr := net.JoinHostPort(*targetIP, *targetPort)

	// NOTE for Pterodactyl:
	// - Ensure that the panel's configuration allows both TCP and UDP on the assigned port.
	// - You may need to enable host networking or configure port mapping for UDP.
	// - Verify that any firewalls allow the necessary inbound and outbound traffic.

	log.Printf("Starting FiveM Proxy on %s, forwarding to backend %s\n", localAddr, serverAddr)

	// Start UDP proxy in a goroutine.
	udpProxy, err := NewUDPProxy(localAddr, serverAddr)
	if err != nil {
		log.Fatalf("[UDP] Failed to start proxy: %v\n", err)
	}
	go udpProxy.Start()

	// Start TCP proxy (this will handle HTTP and any other TCP-based traffic).
	startTCPProxy(localAddr, serverAddr)
}

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

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TCP Proxy

// handleTCPConnection forwards data between the TCP client and backend server.
func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientIP := strings.Split(client.RemoteAddr().String(), ":")[0]
	log.Printf("TCP: Accepted connection from %s", clientIP)
	defer client.Close()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("TCP: Error connecting to backend for %s: %v", clientIP, err)
		return
	}
	defer backend.Close()

	// Read an initial packet (up to 1024 bytes) for logging.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	initialBuf := make([]byte, 1024)
	n, err := client.Read(initialBuf)
	client.SetReadDeadline(time.Time{})
	if err != nil {
		log.Printf("TCP: Error reading initial data from %s: %v", clientIP, err)
		return
	}

	initialData := string(initialBuf[:n])
	log.Printf("TCP: Initial packet from %s: %q", clientIP, initialData[:min(n, 64)])

	// Forward the initial data to the backend.
	_, err = backend.Write(initialBuf[:n])
	if err != nil {
		log.Printf("TCP: Error forwarding initial data from %s: %v", clientIP, err)
		return
	}

	// Bidirectional copy.
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
	log.Printf("TCP: Connection from %s closed after %v", clientIP, time.Since(startTime))
}

// UDP Proxy

// udpClient represents a mapping for a UDP client.
type udpClient struct {
	backendConn *net.UDPConn
	clientAddr  *net.UDPAddr
	lastActive  time.Time
	ch          chan []byte
}

var (
	udpClients   = make(map[string]*udpClient)
	udpClientsMu sync.Mutex
)

// handleUDPClient creates a persistent UDP mapping for a client.
// It reads from a channel (filled by the main UDP loop) and forwards to the backend,
// then waits for a response to send back to the client.
func handleUDPClient(clientAddr *net.UDPAddr, listener *net.UDPConn, targetAddr *net.UDPAddr) {
	clientKey := clientAddr.String()

	backendConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("UDP: Error dialing backend for client %s: %v", clientKey, err)
		return
	}

	ch := make(chan []byte, 100)
	udpClientsMu.Lock()
	udpClients[clientKey] = &udpClient{
		backendConn: backendConn,
		clientAddr:  clientAddr,
		lastActive:  time.Now(),
		ch:          ch,
	}
	udpClientsMu.Unlock()

	buf := make([]byte, 2048)
	// Goroutine: forward packets from client to backend and send response back.
	go func() {
		defer backendConn.Close()
		for {
			select {
			case packet, ok := <-ch:
				if !ok {
					return
				}
				// Forward the packet to backend.
				_, err := backendConn.Write(packet)
				if err != nil {
					log.Printf("UDP: Error writing to backend for %s: %v", clientKey, err)
					continue
				}
				// Set a read deadline for a response.
				backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := backendConn.Read(buf)
				if err == nil && n > 0 {
					// Send response back to client.
					_, err = listener.WriteToUDP(buf[:n], clientAddr)
					if err != nil {
						log.Printf("UDP: Error writing response to client %s: %v", clientKey, err)
					}
				}
			case <-time.After(30 * time.Second):
				// If inactive for 30 seconds, remove the client mapping.
				udpClientsMu.Lock()
				delete(udpClients, clientKey)
				udpClientsMu.Unlock()
				return
			}
		}
	}()
}

// udpProxy continuously reads UDP packets and dispatches them to the appropriate client handler.
func udpProxy(listener *net.UDPConn, targetAddr *net.UDPAddr) {
	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP: Error reading packet: %v", err)
			continue
		}

		clientKey := clientAddr.String()
		udpClientsMu.Lock()
		client, exists := udpClients[clientKey]
		if exists {
			client.lastActive = time.Now()
		} else {
			go handleUDPClient(clientAddr, listener, targetAddr)
			// Allow a short delay for the new client mapping to be created.
			time.Sleep(10 * time.Millisecond)
			client = udpClients[clientKey]
		}
		udpClientsMu.Unlock()

		// Send a copy of the packet to the client's channel.
		if client != nil {
			packet := make([]byte, n)
			copy(packet, buf[:n])
			select {
			case client.ch <- packet:
			default:
				// If the channel is full, drop the packet.
			}
		}
	}
}

func main() {
	// Define flags.
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
	flag.Parse()

	// Ensure required flags are provided.
	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
		os.Exit(1)
	}

	// Start TCP listener.
	tcpListener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Error starting TCP listener on port %s: %v", *listenPort, err)
	}
	defer tcpListener.Close()
	log.Printf("TCP proxy listening on port %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort)

	// Start UDP listener.
	udpAddr, err := net.ResolveUDPAddr("udp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Error resolving UDP address on port %s: %v", *listenPort, err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Error starting UDP listener on port %s: %v", *listenPort, err)
	}
	defer udpListener.Close()
	log.Printf("UDP proxy listening on port %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort)

	// Resolve target UDP address.
	targetUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(*targetIP, *targetPort))
	if err != nil {
		log.Fatalf("Error resolving target UDP address: %v", err)
	}

	// Start UDP proxy in a goroutine.
	go udpProxy(udpListener, targetUDPAddr)

	// Accept and handle TCP connections.
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			log.Printf("TCP: Error accepting connection: %v", err)
			continue
		}
		go handleTCPConnection(conn, *targetIP, *targetPort)
	}
}

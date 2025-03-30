/*
If you understand and want to proceed, repeat the command including --classic.
For example, if installing Go via snap:
    sudo snap install go --classic
Then run your program with:
    go run proxy.go
*/

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// handleTCPConnection establishes a backend connection for the client
// and pipes data bidirectionally.
func handleTCPConnection(client net.Conn, target string) {
	defer client.Close()

	backend, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[TCP] Error connecting to target %s: %v", target, err)
		return
	}
	defer backend.Close()

	log.Printf("[TCP] Proxying connection from %s to %s", client.RemoteAddr(), target)

	// Use a channel to signal when one side closes.
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backend, client)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, backend)
		done <- struct{}{}
	}()

	// Wait until one copy is done.
	<-done
	log.Printf("[TCP] Connection from %s closed", client.RemoteAddr())
}

// startTCPProxy listens for TCP connections on the provided port and
// forwards them to the target.
func startTCPProxy(listenPort, target string) {
	addr := ":" + listenPort
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[TCP] Failed to listen on port %s: %v", listenPort, err)
	}
	defer ln.Close()
	log.Printf("[TCP] Listening on %s, forwarding to %s", addr, target)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[TCP] Accept error: %v", err)
			continue
		}
		go handleTCPConnection(conn, target)
	}
}

// startUDPProxy listens on the given port and forwards UDP packets
// to the target. For every incoming packet, a temporary connection
// is created to forward the packet and read the response.
func startUDPProxy(listenPort, targetIP, targetPort string) {
	localAddr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf("[UDP] Error resolving local address: %v", err)
	}
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalf("[UDP] Error listening on UDP port %s: %v", listenPort, err)
	}
	defer conn.Close()
	log.Printf("[UDP] Listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf("[UDP] Error resolving target address: %v", err)
	}

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP] Read error: %v", err)
			continue
		}
		log.Printf("[UDP] Received %d bytes from %s", n, clientAddr.String())

		// Create a temporary UDP connection to the target.
		backendConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			log.Printf("[UDP] Dial error: %v", err)
			continue
		}

		_, err = backendConn.Write(buf[:n])
		if err != nil {
			log.Printf("[UDP] Write error: %v", err)
			backendConn.Close()
			continue
		}

		// Set a deadline to read the response.
		backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n2, _, err := backendConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[UDP] Read from backend error: %v", err)
			backendConn.Close()
			continue
		}
		backendConn.Close()

		_, err = conn.WriteToUDP(buf[:n2], clientAddr)
		if err != nil {
			log.Printf("[UDP] Write to client error: %v", err)
			continue
		}
		log.Printf("[UDP] Forwarded %d bytes to %s", n2, clientAddr.String())
	}
}

func main() {
	targetIP := flag.String("targetIP", "", "Target server IP address")
	targetPort := flag.String("targetPort", "", "Target server port")
	listenPort := flag.String("listenPort", "", "Port to listen on for both TCP and UDP")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
		os.Exit(1)
	}

	target := net.JoinHostPort(*targetIP, *targetPort)
	log.Printf("Starting simple proxy without DDoS protection...")
	log.Printf("Forwarding connections to %s", target)

	// Start the TCP proxy concurrently.
	go startTCPProxy(*listenPort, target)

	// Start the UDP proxy (runs in the main goroutine).
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

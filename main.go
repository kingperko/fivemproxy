package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleConnection performs initial checks on the client's data,
// blocks potential exploit requests, and then forwards data
// bidirectionally between the client and backend server.
func handleConnection(client net.Conn, remoteAddr, remotePort string) {
	startTime := time.Now()
	clientIP := strings.Split(client.RemoteAddr().String(), ":")[0]
	log.Printf("Accepted connection from %s", clientIP)
	defer client.Close()

	// Connect to backend server.
	backend, err := net.Dial("tcp", net.JoinHostPort(remoteAddr, remotePort))
	if err != nil {
		log.Printf("Error connecting to backend for %s: %v", clientIP, err)
		return
	}
	defer backend.Close()

	// Set a temporary read deadline to get initial data for checking.
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	initialBuf := make([]byte, 1024)
	n, err := client.Read(initialBuf)
	if err != nil {
		log.Printf("Error reading initial data from %s: %v", clientIP, err)
		return
	}
	// Remove the deadline.
	client.SetReadDeadline(time.Time{})

	// Check for common exploit strings.
	initialData := string(initialBuf[:n])
	if strings.Contains(initialData, "players.json") || strings.Contains(initialData, "info.json") {
		log.Printf("Blocked exploit request from %s", clientIP)
		return
	}

	// Log the initial packet (first 64 bytes, if available).
	log.Printf("Initial packet from %s: %q", clientIP, initialData[:min(n, 64)])

	// Forward the initial data to the backend.
	_, err = backend.Write(initialBuf[:n])
	if err != nil {
		log.Printf("Error forwarding initial data from %s: %v", clientIP, err)
		return
	}

	// Start bidirectional copying.
	done := make(chan struct{}, 2)
	go func() {
		// Copy from client to backend.
		io.Copy(backend, client)
		done <- struct{}{}
	}()
	go func() {
		// Copy from backend to client.
		io.Copy(client, backend)
		done <- struct{}{}
	}()

	// Wait for one of the copy operations to finish.
	<-done
	log.Printf("Connection from %s closed after %v", clientIP, time.Since(startTime))
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <listen_port> <remote_address> <remote_port>\n", os.Args[0])
		os.Exit(1)
	}

	listenPort := os.Args[1]
	remoteAddr := os.Args[2]
	remotePort := os.Args[3]

	// Start TCP listener on the specified port.
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Error starting TCP listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %s, forwarding to %s:%s", listenPort, remoteAddr, remotePort)

	// Accept connections continuously.
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn, remoteAddr, remotePort)
	}
}

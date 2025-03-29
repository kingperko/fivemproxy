package main

import (
	"flag"
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
// logs connection info, and then forwards data between the client
// and backend server.
func handleConnection(client net.Conn, targetIP, targetPort string) {
	startTime := time.Now()
	clientIP := strings.Split(client.RemoteAddr().String(), ":")[0]
	log.Printf("Accepted connection from %s", clientIP)
	defer client.Close()

	// Connect to backend server.
	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
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

	// Check for common exploit strings and block if found.
	initialData := string(initialBuf[:n])
	if strings.Contains(initialData, "players.json") || strings.Contains(initialData, "info.json") {
		log.Printf("Blocked exploit request from %s", clientIP)
		return
	}

	// Log the first 64 bytes of the initial data.
	log.Printf("Initial packet from %s: %q", clientIP, initialData[:min(n, 64)])

	// Forward the initial data to the backend.
	_, err = backend.Write(initialBuf[:n])
	if err != nil {
		log.Printf("Error forwarding initial data from %s: %v", clientIP, err)
		return
	}

	// Start bidirectional copy.
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
	log.Printf("Connection from %s closed after %v", clientIP, time.Since(startTime))
}

func main() {
	// Define flags.
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens")
	flag.Parse()

	// Ensure required flags are provided.
	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
		os.Exit(1)
	}

	// Start the TCP listener.
	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Error starting TCP listener on port %s: %v", *listenPort, err)
	}
	defer listener.Close()

	log.Printf("Proxy listening on port %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort)

	// Accept and handle connections.
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(clientConn, *targetIP, *targetPort)
	}
}

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	// Parse command-line flags configured via the egg variables
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Proxy listening port (server allocated)")
	flag.Parse()

	// Validate that all required flags are provided
	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Println("Usage: fivem-proxy -targetIP=<IP> -targetPort=<port> -listenPort=<port>")
		os.Exit(1)
	}

	// Start the TCP listener on the allocated listen port
	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Error starting TCP listener on port %s: %v", *listenPort, err)
	}
	defer listener.Close()
	log.Printf("Proxy listening on port %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort)

	// Accept and handle incoming connections in an infinite loop
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(clientConn, *targetIP, *targetPort)
	}
}

// handleConnection establishes a connection to the target backend server and forwards data between the client and server.
func handleConnection(clientConn net.Conn, targetIP, targetPort string) {
	defer clientConn.Close()

	// Connect to the backend server using the provided IP and port
	serverConn, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("Error connecting to backend server %s:%s: %v", targetIP, targetPort, err)
		return
	}
	defer serverConn.Close()

	// Start forwarding data in both directions concurrently
	go func() {
		_, err := io.Copy(serverConn, clientConn)
		if err != nil {
			log.Printf("Error forwarding data from client to server: %v", err)
		}
	}()
	_, err = io.Copy(clientConn, serverConn)
	if err != nil {
		log.Printf("Error forwarding data from server to client: %v", err)
	}
}

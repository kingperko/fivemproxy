package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

func main() {
	// Command-line flags for backend and listening port.
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		log.Fatalf("Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>", flag.CommandLine.Name())
	}

	// Start listening for incoming TCP connections.
	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Error starting listener on port %s: %v", *listenPort, err)
	}
	defer listener.Close()
	log.Printf("Proxy listening on port %s, forwarding to %s:%s", *listenPort, *targetIP, *targetPort)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(clientConn, *targetIP, *targetPort)
	}
}

func handleConnection(clientConn net.Conn, targetIP, targetPort string) {
	defer clientConn.Close()

	// Extract client IP and port.
	clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()
	clientPort := strconv.Itoa(clientAddr.Port)

	// Connect to the backend server with a timeout.
	backendConn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP, targetPort), 5*time.Second)
	if err != nil {
		log.Printf("Error connecting to backend %s:%s: %v", targetIP, targetPort, err)
		return
	}
	defer backendConn.Close()

	// Construct and send the PROXY protocol header.
	// Format: "PROXY TCP4 <client_ip> <target_ip> <client_port> <target_port>\r\n"
	header := fmt.Sprintf("PROXY TCP4 %s %s %s %s\r\n", clientIP, targetIP, clientPort, targetPort)
	if _, err := backendConn.Write([]byte(header)); err != nil {
		log.Printf("Error sending PROXY header: %v", err)
		return
	}

	log.Printf("Connection from %s forwarded to %s:%s", clientConn.RemoteAddr(), targetIP, targetPort)

	// Bidirectionally copy data between client and backend.
	go func() {
		if _, err := io.Copy(backendConn, clientConn); err != nil {
			log.Printf("Error copying from client to backend: %v", err)
		}
		backendConn.Close()
	}()
	if _, err := io.Copy(clientConn, backendConn); err != nil {
		log.Printf("Error copying from backend to client: %v", err)
	}
}

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

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP address")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Port on which the proxy listens for both TCP and UDP")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port>\n", os.Args[0])
		os.Exit(1)
	}

	// Start TCP proxy in a goroutine.
	go startTCPProxy(*listenPort, *targetIP, *targetPort)

	// Start UDP proxy (blocks).
	startUDPProxy(*listenPort, *targetIP, *targetPort)
}

// startTCPProxy listens on the given TCP port and forwards connections to the backend.
func startTCPProxy(listenPort, targetIP, targetPort string) {
	ln, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Error starting TCP listener on port %s: %v", listenPort, err)
	}
	log.Printf("TCP Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)
	for {
		clientConn, err := ln.Accept()
		if err != nil {
			log.Printf("TCP: Error accepting connection: %v", err)
			continue
		}
		go handleTCPConnection(clientConn, targetIP, targetPort)
	}
}

// handleTCPConnection copies data bidirectionally between the client and the backend.
func handleTCPConnection(client net.Conn, targetIP, targetPort string) {
	defer client.Close()

	backend, err := net.Dial("tcp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Printf("TCP: Error connecting to backend: %v", err)
		return
	}
	defer backend.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backend, client)
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, backend)
	}()

	wg.Wait()
	log.Printf("TCP: Connection from %s closed", client.RemoteAddr().String())
}

// startUDPProxy listens on the given UDP port and forwards packets to the backend.
func startUDPProxy(listenPort, targetIP, targetPort string) {
	addr, err := net.ResolveUDPAddr("udp", ":"+listenPort)
	if err != nil {
		log.Fatalf("UDP: Error resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDP: Error listening on UDP port %s: %v", listenPort, err)
	}
	log.Printf("UDP Proxy listening on port %s, forwarding to %s:%s", listenPort, targetIP, targetPort)
	defer conn.Close()

	backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
	if err != nil {
		log.Fatalf("UDP: Error resolving backend address: %v", err)
	}
	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Fatalf("UDP: Error dialing backend: %v", err)
	}
	defer backendConn.Close()

	buf := make([]byte, 2048)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP: Error reading: %v", err)
			continue
		}

		// Forward the packet to the backend.
		_, err = backendConn.Write(buf[:n])
		if err != nil {
			log.Printf("UDP: Error writing to backend: %v", err)
			continue
		}

		// Read response from the backend (with a short timeout) and send it back to the client.
		backendConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n2, err := backendConn.Read(buf)
		if err == nil && n2 > 0 {
			conn.WriteToUDP(buf[:n2], clientAddr)
		}
	}
}

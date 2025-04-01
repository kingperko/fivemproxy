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

const bufferSize = 65535
const clientTimeout = 60 * time.Second

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

func NewUDPProxy(proxyAddrUDP, serverAddr string) (*UDPProxy, error) {
	clientAddr, err := net.ResolveUDPAddr("udp", proxyAddrUDP)
	if err != nil {
		return nil, err
	}

	clientConn, err := net.ListenUDP("udp", clientAddr)
	if err != nil {
		return nil, err
	}

	serverUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, err
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
			log.Printf("UDP dial error: %v\n", err)
			return
		}

		newConn := &UDPConnection{
			serverConn: serverConn,
			lastActive: time.Now(),
		}

		p.connections.Store(clientAddr.String(), newConn)

		go p.listenServer(clientAddr, newConn)
		conn = newConn
	}

	udpConn := conn.(*UDPConnection)
	udpConn.lastActive = time.Now()
	udpConn.serverConn.Write(data)
}

func (p *UDPProxy) listenServer(clientAddr *net.UDPAddr, conn *UDPConnection) {
	buf := make([]byte, bufferSize)
	for {
		conn.serverConn.SetReadDeadline(time.Now().Add(clientTimeout))
		n, err := conn.serverConn.Read(buf)
		if err != nil {
			p.connections.Delete(clientAddr.String())
			conn.serverConn.Close()
			return
		}

		p.clientConn.WriteToUDP(buf[:n], clientAddr)
	}
}

func (p *UDPProxy) Start() {
	log.Printf("[UDP] Proxy listening on %s\n", p.clientConn.LocalAddr().String())
	buffer := make([]byte, bufferSize)
	for {
		n, clientAddr, err := p.clientConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Client UDP read error: %v\n", err)
			continue
		}
		go p.handleClient(clientAddr, buffer[:n])
	}
}

func handleTCPConnection(client net.Conn, serverAddr string) {
	defer client.Close()

	server, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Printf("TCP dial error: %v\n", err)
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
}

func startTCPProxy(proxyAddrTCP, serverAddr string) {
	listener, err := net.Listen("tcp", proxyAddrTCP)
	if err != nil {
		log.Fatalf("TCP Listen error: %v", err)
	}
	defer listener.Close()

	log.Printf("[TCP] Proxy listening on %s\n", proxyAddrTCP)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("TCP accept error: %v\n", err)
			continue
		}
		go handleTCPConnection(client, serverAddr)
	}
}

func main() {
	targetIP := flag.String("targetIP", "", "Backend server IP")
	targetPort := flag.String("targetPort", "", "Backend server port")
	listenPort := flag.String("listenPort", "", "Local port to listen on for TCP and UDP")
	flag.StringVar(&discordWebhook, "discordWebhook", "", "Discord webhook URL for alerts (optional)")
	flag.Parse()

	if *targetIP == "" || *targetPort == "" || *listenPort == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -targetIP=<IP> -targetPort=<port> -listenPort=<port> [-discordWebhook=<url>]\n", os.Args[0])
		os.Exit(1)
	}

	serverAddr := net.JoinHostPort(*targetIP, *targetPort)
	proxyAddr := ":" + *listenPort

	udpProxy, err := NewUDPProxy(proxyAddr, serverAddr)
	if err != nil {
		log.Fatalf("Failed to start UDP proxy: %v", err)
	}

	go udpProxy.Start()
	startTCPProxy(proxyAddr, serverAddr)
}

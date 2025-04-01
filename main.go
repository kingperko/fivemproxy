package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var (
	targetIP       string
	targetPort     string
	listenPort     string
	httpPort       string
	discordWebhook string
)

func init() {
	flag.StringVar(&targetIP, "targetIP", "127.0.0.1", "Backend server IP")
	flag.StringVar(&targetPort, "targetPort", "30120", "Backend server port")
	flag.StringVar(&listenPort, "listenPort", "30120", "Port for TCP/UDP proxy")
	flag.StringVar(&httpPort, "httpPort", "443", "Port for HTTP caching proxy")
	flag.StringVar(&discordWebhook, "discordWebhook", "", "Optional Discord webhook for DDoS alerts")
	flag.Parse()
}

func main() {
	// Start TCP proxy
	go startTCPProxy()

	// Start UDP proxy
	go startUDPProxy()

	// Start HTTP reverse proxy with caching
	go startHTTPProxy()

	// Block forever
	select {}
}

// --- Rate Limiting and Alerting ---

// A map to track rate limiters per client IP.
var limiterStore = sync.Map{}

// getLimiter returns a rate limiter for the given IP (10 req/sec, burst 20).
func getLimiter(ip string) *rate.Limiter {
	if l, ok := limiterStore.Load(ip); ok {
		return l.(*rate.Limiter)
	}
	lim := rate.NewLimiter(10, 20)
	limiterStore.Store(ip, lim)
	return lim
}

// sendDiscordAlert sends an alert to the configured Discord webhook.
func sendDiscordAlert(message string) {
	if discordWebhook == "" {
		return
	}
	payload := map[string]string{"content": message}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Println("Discord payload marshal error:", err)
		return
	}
	req, err := http.NewRequest("POST", discordWebhook, bytes.NewBuffer(body))
	if err != nil {
		log.Println("Discord request creation error:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Discord alert send error:", err)
		return
	}
	resp.Body.Close()
}

// --- TCP Proxy ---

func startTCPProxy() {
	addr := ":" + listenPort
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("TCP listen error: %v", err)
	}
	log.Printf("TCP proxy listening on %s", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("TCP accept error:", err)
			continue
		}
		go handleTCPConn(conn)
	}
}

func handleTCPConn(client net.Conn) {
	defer client.Close()
	clientIP, _, _ := net.SplitHostPort(client.RemoteAddr().String())
	limiter := getLimiter(clientIP)
	if !limiter.Allow() {
		log.Printf("TCP connection rate limited for %s", clientIP)
		sendDiscordAlert(fmt.Sprintf("TCP connection rate limited for %s", clientIP))
		return
	}

	backendAddr := net.JoinHostPort(targetIP, targetPort)
	server, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Println("TCP dial error:", err)
		return
	}
	defer server.Close()

	// Bidirectionally copy data between client and server.
	go io.Copy(server, client)
	io.Copy(client, server)
}

// --- UDP Proxy ---

func startUDPProxy() {
	addr := ":" + listenPort
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("UDP listen error: %v", err)
	}
	log.Printf("UDP proxy listening on %s", addr)
	clientMap := make(map[string]*udpProxyConn)
	var mu sync.Mutex
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Println("UDP read error:", err)
			continue
		}
		clientKey := clientAddr.String()
		mu.Lock()
		proxyConn, exists := clientMap[clientKey]
		if !exists {
			backendAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, targetPort))
			if err != nil {
				mu.Unlock()
				log.Println("UDP resolve error:", err)
				continue
			}
			proxyConn = newUDPProxyConn(clientAddr, backendAddr, conn)
			clientMap[clientKey] = proxyConn
			go proxyConn.handleUDP(&mu, clientMap)
		}
		mu.Unlock()
		// Copy the received packet into a new slice and send to the proxy handler.
		packet := make([]byte, n)
		copy(packet, buf[:n])
		proxyConn.incoming <- packet
	}
}

type udpProxyConn struct {
	clientAddr  net.Addr
	backendAddr *net.UDPAddr
	lastActive  time.Time
	conn        net.PacketConn
	incoming    chan []byte
}

func newUDPProxyConn(clientAddr net.Addr, backendAddr *net.UDPAddr, conn net.PacketConn) *udpProxyConn {
	return &udpProxyConn{
		clientAddr:  clientAddr,
		backendAddr: backendAddr,
		lastActive:  time.Now(),
		conn:        conn,
		incoming:    make(chan []byte, 1024),
	}
}

func (u *udpProxyConn) handleUDP(mu *sync.Mutex, clientMap map[string]*udpProxyConn) {
	backendConn, err := net.DialUDP("udp", nil, u.backendAddr)
	if err != nil {
		log.Println("UDP dial backend error:", err)
		return
	}
	defer backendConn.Close()

	backendChan := make(chan []byte, 1024)
	done := make(chan struct{})

	// Read from the backend.
	go func() {
		buf := make([]byte, 65535)
		for {
			backendConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := backendConn.Read(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			backendChan <- data
		}
	}()

	// Process incoming packets and backend responses.
	for {
		select {
		case data := <-u.incoming:
			u.lastActive = time.Now()
			_, err := backendConn.Write(data)
			if err != nil {
				log.Println("UDP write to backend error:", err)
			}
		case data := <-backendChan:
			_, err := u.conn.WriteTo(data, u.clientAddr)
			if err != nil {
				log.Println("UDP write to client error:", err)
			}
		case <-time.After(30 * time.Second):
			// Clean up after 30 seconds of inactivity.
			if time.Since(u.lastActive) > 30*time.Second {
				mu.Lock()
				delete(clientMap, u.clientAddr.String())
				mu.Unlock()
				close(done)
				return
			}
		}
	}
}

// --- HTTP Proxy with Caching ---

func startHTTPProxy() {
	// Create a reverse proxy to forward all non-cached requests.
	backendURL := "http://" + net.JoinHostPort(targetIP, targetPort)
	proxy := httputil.NewSingleHostReverseProxy(&http.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(targetIP, targetPort),
	})
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = req.URL.Host
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		limiter := getLimiter(clientIP)
		if !limiter.Allow() {
			log.Printf("HTTP connection rate limited for %s", clientIP)
			sendDiscordAlert(fmt.Sprintf("HTTP connection rate limited for %s", clientIP))
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		// If the request path starts with /files/, attempt to serve from cache.
		if strings.HasPrefix(r.URL.Path, "/files/") {
			serveCached(w, r, backendURL)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	addr := ":" + httpPort
	log.Printf("HTTP proxy listening on %s", addr)
	// For simplicity, this example runs as plain HTTP. TLS can be added if needed.
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}

// serveCached checks for a cached response for /files/ requests and, if absent, fetches and stores it.
func serveCached(w http.ResponseWriter, r *http.Request, backendURL string) {
	cacheDir := "./cache"
	os.MkdirAll(cacheDir, 0755)
	// Create a safe cache key from the full request URI.
	cacheKey := strings.ReplaceAll(r.URL.RequestURI(), "/", "_")
	cachePath := cacheDir + "/" + cacheKey

	// Check if a valid cached file exists (valid for 1 year).
	if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < 365*24*time.Hour {
		http.ServeFile(w, r, cachePath)
		return
	}

	// Otherwise, fetch from backend.
	backendReq, err := http.NewRequestWithContext(context.Background(), r.Method, backendURL+r.URL.RequestURI(), nil)
	if err != nil {
		http.Error(w, "Error creating backend request", http.StatusInternalServerError)
		return
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			backendReq.Header.Add(k, v)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(backendReq)
	if err != nil {
		http.Error(w, "Error fetching from backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers and status code.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Open cache file for writing.
	f, err := os.Create(cachePath)
	if err != nil {
		log.Println("Cache file creation error:", err)
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	mw := io.MultiWriter(w, f)
	io.Copy(mw, resp.Body)
}

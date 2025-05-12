package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	defaultTimeout         = 30 * time.Second
	defaultReadBufferSize  = 32 * 1024 // 32 KB
	webSocketMagicString   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	defaultHandshakeStatus = "101 Switching Protocols"
)

// ProxyConfig holds the configuration for the SSH proxy
type ProxyConfig struct {
	address        string
	dstAddress     string
	tlsAddress     string
	handshakeCode  string
	tlsEnabled     bool
	tlsPrivateKey  string
	tlsPublicKey   string
	tlsMode        string
	logger         *slog.Logger
}

// ProxyConnection interface for network connections
type ProxyConnection interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

func main() {
	// Setup logger with structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Parse command-line flags
	config := parseFlags(logger)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	go handleSignals(cancel, logger)

	// Create wait group for managing goroutines
	var wg sync.WaitGroup

	// Start servers based on configuration
	if err := startServers(ctx, &wg, config); err != nil {
		logger.Error("Failed to start servers", "error", err)
		os.Exit(1)
	}

	// Wait for all servers to complete
	wg.Wait()
}

// parseFlags handles command-line flag parsing
func parseFlags(logger *slog.Logger) *ProxyConfig {
	config := &ProxyConfig{
		logger: logger,
	}

	flag.StringVar(&config.address, "addr", ":2086", "Set port for listening clients. Ex.: 127.0.0.1:2086")
	flag.StringVar(&config.tlsAddress, "tls_addr", ":443", "Set port for listening clients if using TLS mode. Ex.: 443")
	flag.StringVar(&config.dstAddress, "dstAddr", "127.0.0.1:22", "Set internal IP for SSH server redirection. Ex.: 127.0.0.1:22")
	flag.StringVar(&config.handshakeCode, "custom_handshake", "", "Set custom HTTP code for response. Ex.: 101/200.. etc.")
	flag.BoolVar(&config.tlsEnabled, "tls", false, "Enable TLS")
	flag.StringVar(&config.tlsPrivateKey, "private_key", "/home/example/private.pem", "Path to private certificate if using TLS.")
	flag.StringVar(&config.tlsPublicKey, "public_key", "/home/example/public.key", "Path to public certificate if using TLS.")
	flag.StringVar(&config.tlsMode, "tls_mode", "handshake", "TLS mode: 'handshake' responds with status 101/200, 'stunnel' does not respond.")

	flag.Parse()
	return config
}

// startServers initializes and starts HTTP and TLS servers
func startServers(ctx context.Context, wg *sync.WaitGroup, config *ProxyConfig) error {
	serverErrChan := make(chan error, 2)

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErrChan <- startHTTPServer(ctx, config)
	}()

	// Start TLS server if enabled
	if config.tlsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serverErrChan <- startTLSServer(ctx, config)
		}()
	}

	// Wait for any server to fail
	go func() {
		err := <-serverErrChan
		if err != nil {
			config.logger.Error("Server error", "error", err)
			// Cancel context to trigger shutdown
			os.Exit(1)
		}
	}()

	return nil
}

// startHTTPServer sets up the HTTP proxy server
func startHTTPServer(ctx context.Context, config *ProxyConfig) error {
	addr, err := net.ResolveTCPAddr("tcp", config.address)
	if err != nil {
		return fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP server: %w", err)
	}
	defer listener.Close()

	config.logger.Info("HTTP Server listening", 
		slog.String("address", config.address), 
		slog.String("redirect", config.dstAddress))

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.AcceptTCP()
			if err != nil {
				config.logger.Error("Failed to accept TCP connection", "error", err)
				continue
			}

			// Configure keep-alive
			if err := conn.SetKeepAlive(true); err != nil {
				config.logger.Error("Failed to set keep-alive", "error", err)
				conn.Close()
				continue
			}

			go handleConnection(conn, config, false)
		}
	}
}

// startTLSServer sets up the TLS proxy server
func startTLSServer(ctx context.Context, config *ProxyConfig) error {
	cert, err := tls.LoadX509KeyPair(config.tlsPrivateKey, config.tlsPublicKey)
	if err != nil {
		return fmt.Errorf("error loading TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12, // Enforce modern TLS
	}

	listener, err := tls.Listen("tcp", config.tlsAddress, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on TLS server: %w", err)
	}
	defer listener.Close()

	config.logger.Info("TLS Server listening", 
		slog.String("address", config.tlsAddress), 
		slog.String("redirect", config.dstAddress))

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.Accept()
			if err != nil {
				config.logger.Error("Failed to accept TLS connection", "error", err)
				continue
			}

			go handleConnection(conn, config, true)
		}
	}
}

// handleConnection manages individual proxy connections
func handleConnection(clientConn ProxyConnection, config *ProxyConfig, isTLSClient bool) {
	defer clientConn.Close()

	// Perform WebSocket handshake or custom handshake
	if err := performHandshake(clientConn, config); err != nil {
		config.logger.Error("Handshake failed", "error", err)
		return
	}

	// Establish connection to destination
	destConn, err := net.DialTimeout("tcp", config.dstAddress, defaultTimeout)
	if err != nil {
		config.logger.Error("Failed to connect to destination", "error", err)
		return
	}
	defer destConn.Close()

	// Handle connection based on TLS mode
	if isTLSClient && config.tlsMode == "stunnel" {
		// Direct stream copying for stunnel mode
		return streamConnections(destConn, clientConn)
	}

	// Discard initial payload for standard mode
	if err := discardPayload(clientConn); err != nil {
		config.logger.Error("Failed to discard payload", "error", err)
		return
	}

	// Stream connections
	streamConnections(destConn, clientConn)
}

// performHandshake handles WebSocket or custom handshake
func performHandshake(conn ProxyConnection, config *ProxyConfig) error {
	if config.handshakeCode != "" {
		// Custom handshake response
		_, err := conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %s Ok\r\n\r\n", config.handshakeCode)))
		return err
	}

	// Default WebSocket handshake
	secWebSocketKey := "Y2FmcnQ2NTRlY2Z2Z3ludTg="
	h := sha1.New()
	h.Write([]byte(secWebSocketKey + webSocketMagicString))
	secWebSocketAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	resp := fmt.Sprintf("HTTP/1.1 %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n",
		defaultHandshakeStatus, secWebSocketAccept)

	_, err := conn.Write([]byte(resp))
	return err
}

// discardPayload reads and discards initial payload
func discardPayload(conn ProxyConnection) error {
	buffer := make([]byte, defaultReadBufferSize)
	_, err := io.ReadAtLeast(conn, buffer, 5)
	return err
}

// streamConnections handles bidirectional data streaming
func streamConnections(src, dst ProxyConnection) {
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(dst, src)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(src, dst)
		errChan <- err
	}()

	// Wait for first error or both streams to complete
	<-errChan
}

// handleSignals manages graceful shutdown
func handleSignals(cancel context.CancelFunc, logger *slog.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, 
		syscall.SIGINT, 
		syscall.SIGTERM, 
		syscall.SIGQUIT)

	sig := <-sigChan
	logger.Info("Received shutdown signal", "signal", sig)
	cancel()
}

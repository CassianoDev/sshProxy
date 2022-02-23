package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type proxy struct {
	tls *bool
	address, dstAddress, tlsAddress,
	handshakeCode, tlsPrivateKey,
	tlsPublicKey, tlsMode *string
}

type sshProxy interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
}

func main() {
	var wg sync.WaitGroup
	SSHProxy := proxy{
		address:       flag.String("addr", ":2086", "Set port for listen clients. Ex.: 127.0.0.1:2086"),
		tlsAddress:    flag.String("tls_addr", ":443", "Set port for listen clients if use TLS mode. Ex.: 443"),
		dstAddress:    flag.String("dstAddr", "127.0.0.1:22", "Set internal ip for SSH server redir. Ex.: 127.0.0.1:22"),
		handshakeCode: flag.String("custom_handshake", "", "Set HTTP code custom for response user. Ex.: 101/200.. etc. "),
		tls:           flag.Bool("tls", false, "Set true to use TLS"),
		tlsPrivateKey: flag.String("private_key", "/home/example/private.pem", "Set path to your private certificate if use TLS."),
		tlsPublicKey:  flag.String("public_key", "/home/example/public.key", "Set path to your public certificate if use TLS."),
		tlsMode:       flag.String("tls_mode", "handshake", "Set TLS mode, if 'handshake' set, response  client with status 101/200 etc, if 'stunnel' set, not response client with status."),
	}
	flag.Parse()
	if *SSHProxy.tls {
		go SSHProxy.ServerTLS(&wg)
	}

	go SSHProxy.ServerHTTP(&wg)

	wg.Add(1)
	wg.Wait()
}

func (p *proxy) ServerTLS(wg *sync.WaitGroup) {
	defer wg.Done()
	cert, err := tls.LoadX509KeyPair(*p.tlsPrivateKey, *p.tlsPublicKey)
	if err != nil {
		log.Fatal("Error loading certificate. ", err.Error())
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
	}
	conn, errConn := tls.Listen("tcp", *p.tlsAddress, tlsCfg)
	if errConn != nil {
		log.Fatal("Failed to listen TLS server", errConn.Error())
	}
	log.Println("TLS Server listening on ", *p.tlsAddress, " redirect to -> ", *p.dstAddress)
	for {
		ClientConn, err := conn.Accept()

		if err != nil {
			log.Println("Failed to accept TLS client ", err.Error())
			continue
		}
		go p.Handler(ClientConn, true)
	}
}

func (p *proxy) ServerHTTP(wg *sync.WaitGroup) {
	defer wg.Done()
	taddr, errNet := net.ResolveTCPAddr("tcp", *p.address)
	if errNet != nil {
		log.Println(errNet.Error())
		return
	}
	conn, errConn := net.ListenTCP("tcp", taddr)

	if errConn != nil {
		log.Fatal("Failed to listen HTTP server ", errConn.Error())
	}
	log.Println("HTTP Server listening on ", *p.address, "redirect to -> ", *p.dstAddress)
	for {
		ClientConn, err := conn.AcceptTCP()
		if err != nil {
			log.Println("Failed to accepted stream on HTTP mode: ", err.Error())
			continue
		}
		err = ClientConn.SetKeepAlive(true)
		if err != nil {
			log.Println("Failed to set keepalive: ", err.Error())
			continue
		}
		go p.Handler(ClientConn, false)
	}
}

func (p *proxy) Handler(ClientConn sshProxy, tlsClient bool) {
	if len(*p.handshakeCode) > 0 {
		_, err := ClientConn.Write([]byte("HTTP/1.1 " + *p.handshakeCode + "Ok\r\n\r\n"))
		if err != nil {
			return
		}
	} else {
		_, err := ClientConn.Write([]byte("HTTP/1.1 101 Ok\r\n\r\n"))
		if err != nil {
			return
		}
	}
	sshConn, err := net.DialTimeout("tcp", *p.dstAddress, 15*time.Second)
	if err != nil {
		log.Println("Failed to call destination. ", err.Error())
		return
	}

	if tlsClient && *p.tlsMode == "stunnel" {
		go copyStream(sshConn, ClientConn)
		go copyStream(ClientConn, sshConn)
	} else {
		if p.discardPayload(ClientConn) == nil {
			go copyStream(sshConn, ClientConn)
			go copyStream(ClientConn, sshConn)
		} else {
			log.Println("Failed on receive payload")
			return
		}
	}

}

func (p *proxy) discardPayload(ClientConn sshProxy) error {
	bft := make([]byte, 2048)
	_, err := io.ReadAtLeast(ClientConn, bft, 5)

	if err != nil {
		return err
	} else {
		return nil
	}
}

func copyStream(input, output sshProxy) {
	_, err := io.Copy(input, output)
	if err != nil {
		return
	}
}

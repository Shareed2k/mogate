package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fixture:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("expected server or request")
	}
	switch args[0] {
	case "server":
		return runServer(ctx, args[1:])
	case "request":
		return runRequest(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServer(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	address := flags.String("address", ":8080", "TCP and UDP listen address")
	response := flags.String("response", "remote", "response payload")
	if err := flags.Parse(args); err != nil {
		return err
	}
	tcpListener, err := net.Listen("tcp", *address)
	if err != nil {
		return err
	}
	defer tcpListener.Close()
	udpAddress, err := net.ResolveUDPAddr("udp", *address)
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	results := make(chan error, 2)
	go func() { results <- serveTCP(ctx, tcpListener, []byte(*response)) }()
	go func() { results <- serveUDP(ctx, udpConn, []byte(*response)) }()
	go func() {
		<-ctx.Done()
		_ = tcpListener.Close()
		_ = udpConn.Close()
	}()
	first := <-results
	if ctx.Err() != nil {
		return nil
	}
	return first
}

func serveTCP(ctx context.Context, listener net.Listener, response []byte) error {
	var clients sync.WaitGroup
	defer clients.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		clients.Add(1)
		go func() {
			defer clients.Done()
			defer conn.Close()
			buffer := make([]byte, 4096)
			if count, err := conn.Read(buffer); err == nil {
				if bytes.HasPrefix(buffer[:count], []byte("GET ")) || bytes.HasPrefix(buffer[:count], []byte("HEAD ")) {
					head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(response))
					_, _ = conn.Write([]byte(head))
					if bytes.HasPrefix(buffer[:count], []byte("GET ")) {
						_, _ = conn.Write(response)
					}
				} else {
					_, _ = conn.Write(response)
				}
			}
		}()
	}
}

func serveUDP(ctx context.Context, conn *net.UDPConn, response []byte) error {
	buffer := make([]byte, 65507)
	for {
		_, client, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if _, err := conn.WriteToUDP(response, client); err != nil {
			return err
		}
	}
}

func runRequest(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("request", flag.ContinueOnError)
	network := flags.String("network", "tcp", "tcp or udp")
	address := flags.String("address", "", "destination address")
	payload := flags.String("payload", "probe", "request payload")
	timeout := flags.Duration("timeout", 10*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(requestCtx, *network, *address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(*timeout))
	if _, err := conn.Write([]byte(*payload)); err != nil {
		return err
	}
	buffer := make([]byte, 4096)
	count, err := conn.Read(buffer)
	if err != nil {
		return err
	}
	fmt.Print(string(buffer[:count]))
	return nil
}

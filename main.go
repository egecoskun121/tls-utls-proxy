// tls-utls-proxy is a private, loopback/internal-network-only HTTP proxy that terminates TLS
// to the real origin itself using uTLS, so the resulting ClientHello is byte-for-byte a real
// browser's — not the caller's own TLS stack. The caller talks plain HTTP to this proxy and
// names the real destination via the X-Target-URL header; this proxy does the actual TLS
// handshake, forwards the request, and relays the response back in plaintext.
//
// This is NOT a general CONNECT-style forward proxy: a CONNECT proxy just relays encrypted
// bytes, so the client's own TLS stack still performs the handshake and the fingerprint doesn't
// change. Here the proxy itself is the TLS client to the origin.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const targetHeader = "X-Target-URL"

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func main() {
	listenAddr := envOr("LISTEN_ADDR", ":8880")
	helloID := clientHelloID(envOr("CLIENT_HELLO", "chrome"))

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", proxyHandler(helloID))

	log.Printf("tls-utls-proxy listening on %s (client hello: %s)", listenAddr, os.Getenv("CLIENT_HELLO"))
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}

func clientHelloID(name string) utls.ClientHelloID {
	switch strings.ToLower(name) {
	case "firefox":
		return utls.HelloFirefox_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func proxyHandler(helloID utls.ClientHelloID) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetRaw := r.Header.Get(targetHeader)
		if targetRaw == "" {
			http.Error(w, targetHeader+" header is required", http.StatusBadRequest)
			return
		}

		target, err := url.Parse(targetRaw)
		if err != nil || target.Scheme != "https" || target.Host == "" {
			http.Error(w, "invalid "+targetHeader+" (must be an absolute https:// URL)", http.StatusBadRequest)
			return
		}
		target.Path = r.URL.Path
		target.RawQuery = r.URL.RawQuery

		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		tlsConn, err := dialUTLS(ctx, target.Host, helloID)
		if err != nil {
			http.Error(w, fmt.Sprintf("uTLS dial to %s failed: %v", target.Host, err), http.StatusBadGateway)
			return
		}
		defer tlsConn.Close()

		outReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), r.Body)
		if err != nil {
			http.Error(w, "could not build outbound request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		copyHeaders(r.Header, outReq.Header, targetHeader)
		outReq.Host = hostOnly(target.Host)

		if err := outReq.Write(tlsConn); err != nil {
			http.Error(w, "could not write outbound request: "+err.Error(), http.StatusBadGateway)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), outReq)
		if err != nil {
			http.Error(w, "could not read origin response: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyHeaders(resp.Header, w.Header(), "")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

func dialUTLS(ctx context.Context, hostPort string, helloID utls.ClientHelloID) (*utls.UConn, error) {
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	host := hostOnly(hostPort)

	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	tlsConn := utls.UClient(rawConn, &utls.Config{ServerName: host}, helloID)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake: %w", err)
	}
	return tlsConn, nil
}

func hostOnly(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func copyHeaders(src http.Header, dst http.Header, skip string) {
	for name, values := range src {
		if hopByHopHeaders[name] || strings.EqualFold(name, skip) || strings.EqualFold(name, "Host") {
			continue
		}
		for _, v := range values {
			dst.Add(name, v)
		}
	}
}

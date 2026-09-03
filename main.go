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
	"encoding/base64"
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
	"golang.org/x/net/http2"
)

// upstreamProxy, when configured, is an HTTP CONNECT proxy (e.g. a residential proxy
// provider's gateway) this process tunnels through before doing its own uTLS handshake.
// Point it at a *rotating* gateway endpoint and IP rotation falls out for free: this process
// opens a fresh upstream connection per request, and a rotating gateway hands out a new exit IP
// per connection.
type upstreamProxy struct {
	addr string // host:port
	user string
	pass string
}

func upstreamProxyFromEnv() *upstreamProxy {
	addr := os.Getenv("UPSTREAM_PROXY_ADDR")
	if addr == "" {
		return nil
	}
	return &upstreamProxy{
		addr: addr,
		user: os.Getenv("UPSTREAM_PROXY_USER"),
		pass: os.Getenv("UPSTREAM_PROXY_PASS"),
	}
}

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
	upstream := upstreamProxyFromEnv()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", proxyHandler(helloID, upstream))

	upstreamDesc := "none (dialing origins directly)"
	if upstream != nil {
		upstreamDesc = upstream.addr
	}
	log.Printf("tls-utls-proxy listening on %s (client hello: %s, upstream proxy: %s)",
		listenAddr, os.Getenv("CLIENT_HELLO"), upstreamDesc)
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

func proxyHandler(helloID utls.ClientHelloID, upstream *upstreamProxy) http.HandlerFunc {
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

		tlsConn, err := dialUTLS(ctx, target.Host, helloID, upstream)
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

		var resp *http.Response
		if tlsConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
			resp, err = doHTTP2(tlsConn, outReq)
		} else {
			resp, err = doHTTP1(tlsConn, outReq)
		}
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

// doHTTP1 sends outReq as a plain HTTP/1.1 message over conn and parses the response the
// same way — used when ALPN negotiated "http/1.1" (or nothing) during the uTLS handshake.
func doHTTP1(conn *utls.UConn, outReq *http.Request) (*http.Response, error) {
	if err := outReq.Write(conn); err != nil {
		return nil, fmt.Errorf("could not write outbound request: %w", err)
	}
	return http.ReadResponse(bufio.NewReader(conn), outReq)
}

// doHTTP2 speaks HTTP/2 over conn — used when ALPN negotiated "h2" during the uTLS handshake,
// which real browsers do by default and a plain http.ReadResponse (HTTP/1.x only) can't parse.
// NewClientConn runs the HTTP/2 client preface and SETTINGS exchange on top of the
// already-established uTLS connection; the TLS handshake itself is untouched.
func doHTTP2(conn *utls.UConn, outReq *http.Request) (*http.Response, error) {
	t := &http2.Transport{}
	cc, err := t.NewClientConn(conn)
	if err != nil {
		return nil, fmt.Errorf("http2 client conn: %w", err)
	}
	return cc.RoundTrip(outReq)
}

func dialUTLS(ctx context.Context, hostPort string, helloID utls.ClientHelloID, upstream *upstreamProxy) (*utls.UConn, error) {
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	host := hostOnly(hostPort)

	rawConn, err := dialRaw(ctx, hostPort, upstream)
	if err != nil {
		return nil, err
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

// dialRaw returns a plaintext net.Conn to hostPort — either a direct TCP connection, or, when an
// upstreamProxy is configured, a connection tunneled through it via HTTP CONNECT. Either way the
// caller does its own TLS on top: the upstream proxy only ever sees opaque TLS bytes after the
// CONNECT handshake, it never terminates TLS itself.
func dialRaw(ctx context.Context, hostPort string, upstream *upstreamProxy) (net.Conn, error) {
	dialer := &net.Dialer{}

	if upstream == nil {
		conn, err := dialer.DialContext(ctx, "tcp", hostPort)
		if err != nil {
			return nil, fmt.Errorf("tcp dial: %w", err)
		}
		return conn, nil
	}

	conn, err := dialer.DialContext(ctx, "tcp", upstream.addr)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	connectReq := "CONNECT " + hostPort + " HTTP/1.1\r\nHost: " + hostPort + "\r\n"
	if upstream.user != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(upstream.user + ":" + upstream.pass))
		connectReq += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT write: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT rejected: %s", resp.Status)
	}
	if reader.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("upstream proxy sent data before CONNECT completed")
	}

	return conn, nil
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

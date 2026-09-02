# tls-utls-proxy

A private, loopback/internal-network-only HTTP proxy that terminates TLS to the real origin
using [uTLS](https://github.com/refraction-networking/utls) — Go's `crypto/tls` fork built
specifically to produce byte-for-byte real-browser `ClientHello`s. The caller talks plain HTTP
to this proxy; this proxy does the actual TLS handshake to the origin, so the resulting
fingerprint is a genuine browser's, not the caller's own TLS stack's.

## Why this exists, and why it's not a CONNECT proxy

A standard HTTP `CONNECT` proxy just relays encrypted bytes — the *client's own* TLS stack still
performs the handshake with the origin, so the fingerprint doesn't change no matter what the
proxy does. To actually change the fingerprint, the proxy itself has to be the TLS client to the
origin. That's what this does: it terminates TLS on the caller's behalf using uTLS, then forwards
the request over that connection and relays the plaintext response back.

This exists because a Bouncy-Castle-based Java approach (see
[tls-fingerprint-java](https://github.com/egecoskun121/tls-fingerprint-java)) hits a hard ceiling:
BC's public API always writes zero-length-payload extensions before non-empty ones, so it can
approximate a browser's cipher/group/ALPN/version preferences but never its true interleaved
extension order. uTLS doesn't have that limitation — verified end-to-end against
[tls.peet.ws/api/all](https://tls.peet.ws/api/all): the Chrome profile here reproduces the real,
fully interleaved extension order (including `ECH` and `application_settings`/ALPS, which the BC
approach can't produce at all).

## Usage

The caller sends a plain HTTP request to this proxy with the real destination in the
`X-Target-URL` header:

```bash
curl -H "X-Target-URL: https://example.com/some/path" http://127.0.0.1:8880/some/path
```

- Method, headers (minus `X-Target-URL` and hop-by-hop headers), and body are forwarded as-is.
- The response status, headers, and body are relayed back unchanged.
- `GET /healthz` — liveness check.

## Configuration (env vars)

- `LISTEN_ADDR` — default `:8880`
- `CLIENT_HELLO` — `chrome` (default) or `firefox`, selects the uTLS `ClientHelloID`
- `UPSTREAM_PROXY_ADDR` — optional, `host:port` of an upstream HTTP CONNECT proxy (e.g. a
  residential proxy provider's gateway). When set, this process tunnels through it via `CONNECT`
  before doing its own uTLS handshake — the upstream proxy only ever sees opaque TLS bytes, it
  never terminates TLS itself, so the fingerprint stays genuine. A fresh upstream connection is
  opened per request, so pointing this at a *rotating* gateway endpoint rotates the exit IP for
  free, with no extra logic needed here.
- `UPSTREAM_PROXY_USER` / `UPSTREAM_PROXY_PASS` — optional, sent as `Proxy-Authorization: Basic`
  on the `CONNECT` request when `UPSTREAM_PROXY_ADDR` is set

## Running

```bash
docker build -t tls-utls-proxy .
docker run -p 8880:8880 -e CLIENT_HELLO=chrome tls-utls-proxy
```

**This must never be exposed publicly.** It has no auth and will happily proxy a caller-supplied
`X-Target-URL` to anywhere — bind it to loopback or an internal-only Docker network, never map
its port to a public interface.

## Security note

This proxy changes what a TLS handshake *looks like* on the wire; it does not change what gets
*trusted*. Certificate validation for the origin connection is uTLS's own (Go's standard library
`crypto/x509` verification), unmodified.

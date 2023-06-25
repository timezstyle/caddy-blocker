package caddy_blocker

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/projectdiscovery/expirablelru"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("blocker", parseCaddyfile)
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func NewLoggingResponseWriter(w http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{w, http.StatusOK}
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// Middleware implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type Middleware struct {
	MaxUnAuthTimes string `json:"max_unauth_times"`
	maxUnAuthTimes int

	BlockDuration string `json:"block_duration"`
	blockDuration time.Duration

	CacheSize string `json:"cache_size"`
	lruCache  *expirablelru.Cache

	w io.Writer
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.blocker",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Middleware) Provision(ctx caddy.Context) error {
	var err error
	m.blockDuration, err = time.ParseDuration(m.BlockDuration)
	if err != nil {
		return fmt.Errorf("block_duration is wrong with value: %v", m.BlockDuration)
	}
	cacheSize, err := strconv.Atoi(m.CacheSize)
	if err != nil {
		return fmt.Errorf("cache_size is wrong with value: %v", m.CacheSize)
	}
	m.lruCache = expirablelru.NewExpirableLRU(cacheSize, nil, m.blockDuration, 0)

	m.maxUnAuthTimes, err = strconv.Atoi(m.MaxUnAuthTimes)
	if err != nil {
		return fmt.Errorf("max_unauth_times is wrong with value: %v", m.MaxUnAuthTimes)
	}

	m.w = os.Stdout
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	if m.w == nil {
		return fmt.Errorf("no writer")
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, port, _ := net.SplitHostPort(r.RemoteAddr)
	var unAuthTimes int
	if v, ok := m.lruCache.Get(ip); ok {
		unAuthTimes = v.(int)
	}
	if unAuthTimes > m.maxUnAuthTimes {
		w.WriteHeader(http.StatusUnauthorized)
		return nil
	}

	lrw := NewLoggingResponseWriter(w)
	err := next.ServeHTTP(lrw, r)
	if err != nil {
		return err
	}

	switch lrw.statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		m.lruCache.Add(ip, unAuthTimes+1)
		m.w.Write([]byte(fmt.Sprintf("!!!! %v, %v, %v", lrw.statusCode, ip, port)))
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.CacheSize, &m.MaxUnAuthTimes, &m.BlockDuration) {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

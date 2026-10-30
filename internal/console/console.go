// Package console is the approver's page: an embedded shell, script and
// stylesheet, and a JSON API that lists and answers approvals and writes
// pauses through internal/approvals and internal/pause, as the approvals and
// pause commands do. It adds no authority: whoever can write the directory
// and the pause file can already do everything the page does.
//
// The page is reachable only at the one loopback address it was bound to.
// The token it was started with is good for one thing, once: the script
// trades it at SessionPath for a session token, which every other request
// carries in TokenHeader. Its JSON is private to its own script and carries
// no version.
package console

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/guardana/control/internal/approvals"
)

// TokenHeader carries a token on every API request. A header, unlike a
// cookie, is sent by no page but the one whose script holds the token.
const TokenHeader = "X-Console-Token"

// SessionPath is where the printed token is traded for the session token.
const SessionPath = "/api/session"

// PrintedTokenLife bounds how long a printed token nobody traded can still be
// traded. The link it travels in is kept in the browser's history, so it has
// to be worth nothing there.
const PrintedTokenLife = 10 * time.Minute

// tokenBytes is a token's entropy before encoding.
const tokenBytes = 32

// maxBodyBytes bounds a request body; every answer the page sends fits in it.
const maxBodyBytes = 4 << 10

// The refusals a tab without a valid token reads.
const (
	noSession = "this tab holds no session of this page; start the console command again and open the link it prints"
	spentLink = "this link was used already or is more than ten minutes old; start the console command again and open the link it prints"
)

// contentSecurityPolicy allows the page's own script and stylesheet and
// nothing else: no inline script, no frame around it, no form that submits,
// and no string that reaches a markup sink.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'"

// securityHeaders go on every answer, a refusal included.
var securityHeaders = [...][2]string{
	{"Content-Security-Policy", contentSecurityPolicy},
	{"X-Frame-Options", "DENY"},
	{"Cache-Control", "no-store"},
	{"Referrer-Policy", "no-referrer"},
	{"X-Content-Type-Options", "nosniff"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
}

// Options is what one page serves.
type Options struct {
	// Approvals is the approver's handle on the directory. The page never
	// closes it.
	Approvals *approvals.Approver
	// Directory is the approvals directory as the operator named it, shown on
	// the page and never opened by it.
	Directory string
	// PauseFile is the pause file the page reads and writes, or empty for a
	// page that shows and writes no pause.
	PauseFile string
	// ApproverID is recorded on every answer the page files. It is the
	// starter's claim, and nothing authenticates it.
	ApproverID string
	// Host is the address the page was bound to, exactly as a browser names
	// it in Host: 127.0.0.1 and the port.
	Host string
	// Token is what NewToken returned, and what the starter printed.
	Token string
	// Now is the page's clock; nil is the system's.
	Now func() time.Time
}

// NewToken returns 32 bytes from the system's randomness in unpadded
// base64url, which is what a URL fragment carries without escaping.
func NewToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error; it aborts the process instead.
	return base64.RawURLEncoding.EncodeToString(b)
}

// New returns the page's handler. It refuses a missing store, a host that is
// not 127.0.0.1 and a port, a token that is not NewToken's shape, and an
// approver id the store would refuse on every answer. The printed token's
// life starts now.
func New(o Options) (http.Handler, error) {
	if o.Approvals == nil {
		return nil, errors.New("console: no approvals store")
	}
	ap, err := netip.ParseAddrPort(o.Host)
	if err != nil || ap.Addr() != netip.AddrFrom4([4]byte{127, 0, 0, 1}) || ap.Port() == 0 || ap.String() != o.Host {
		return nil, fmt.Errorf("console: the host %q is not 127.0.0.1 and a port", o.Host)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(o.Token); err != nil || len(raw) != tokenBytes {
		return nil, errors.New("console: the token is not 32 bytes in unpadded base64url")
	}
	if err := CheckApproverID(o.ApproverID); err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &page{o: o, origin: "http://" + o.Host, now: now, printedUntil: now().Add(PrintedTokenLife)}, nil
}

// CheckApproverID holds an approver id to what the approvals store holds an
// answer's approver to, the reserved authn: prefix included, so a page never
// starts with an id every answer would be refused under. The store checks it
// again on every answer.
func CheckApproverID(id string) error {
	return approvals.CheckApproverID(id)
}

type page struct {
	o      Options
	origin string
	now    func() time.Time

	// mu guards the tokens: the printed one is traded once, and the session
	// token exists only after that.
	mu           sync.Mutex
	printedUntil time.Time
	traded       bool
	session      string
}

// ServeHTTP answers one request. The checks run before the route: a request
// the page would refuse learns nothing about which paths exist.
func (p *page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	for _, kv := range securityHeaders {
		h.Set(kv[0], kv[1])
	}
	// A name that resolves to the loopback is still another site's name; only
	// the literal address the page was bound to reaches it.
	if r.Host != p.o.Host {
		refuse(w, http.StatusForbidden, "this page answers only at the address it printed")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		serveAsset(w, r)
		return
	}
	if msg := p.unauthorized(r); msg != "" {
		refuse(w, http.StatusUnauthorized, msg)
		return
	}
	if msg := p.crossSite(r); msg != "" {
		refuse(w, http.StatusForbidden, msg)
		return
	}
	p.serveAPI(w, r)
}

// unauthorized returns the refusal of a request without the one token its
// path takes, or "": the printed token at SessionPath while it can still be
// traded, and the session token everywhere else.
func (p *page) unauthorized(r *http.Request) string {
	got := r.Header.Values(TokenHeader)
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.Path == SessionPath {
		if len(got) != 1 || !p.printedLive(got[0]) {
			return spentLink
		}
		return ""
	}
	if len(got) != 1 || p.session == "" || !same(got[0], p.session) {
		return noSession
	}
	return ""
}

// printedLive reports whether token is the printed one and can still be
// traded. mu is held. The life holds on the wall clock as well as on the
// monotonic one, which some systems stop while the machine sleeps.
func (p *page) printedLive(token string) bool {
	now := p.now()
	return same(token, p.o.Token) && !p.traded &&
		now.Before(p.printedUntil) && now.Round(0).Before(p.printedUntil.Round(0))
}

// same compares in constant time. The length is not secret: every token has
// the same one.
func same(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// crossSite refuses a request a browser says came from anywhere but this
// page. A header the browser did not send is not a refusal: a client that is
// not a browser sends neither, and the token has already been checked.
func (p *page) crossSite(r *http.Request) string {
	if origin := r.Header.Values("Origin"); len(origin) > 0 && (len(origin) != 1 || origin[0] != p.origin) {
		return "a request from another origin is refused"
	}
	if site := r.Header.Values("Sec-Fetch-Site"); len(site) > 0 && (len(site) != 1 || site[0] != "same-origin") {
		return "a request the browser did not make from this page is refused"
	}
	return ""
}

// startSession trades the printed token for the session token, once. The
// check is made again under the lock, so of two trades racing only one wins.
func (p *page) startSession(w http.ResponseWriter, r *http.Request, _ any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.printedLive(r.Header.Get(TokenHeader)) {
		refuse(w, http.StatusUnauthorized, spentLink)
		return
	}
	p.traded, p.session = true, NewToken()
	reply(w, http.StatusOK, struct {
		Session string `json:"session"`
	}{p.session})
}

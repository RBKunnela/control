package gatewayconfig

import (
	"fmt"
	"math"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/guardana/control/internal/peercred"
)

// AccountID is the numeric user id of an account a key names, or none.
type AccountID struct {
	ID  uint32
	Set bool
}

// accountField is a key naming one account by its numeric id, with no
// default. The largest id is (uid_t)-1, which names no account.
func accountField[T any](path string, get func(*T) *AccountID) field[T] {
	return field[T]{
		path: path, kind: "a numeric user id",
		set: func(t *T, v string) error {
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil || n == math.MaxUint32 {
				return fmt.Errorf("not an account's numeric user id: %s", quoteValue(v))
			}
			*get(t) = AccountID{ID: uint32(n), Set: true}
			return nil
		},
		show: func(t *T) string {
			if a := *get(t); a.Set {
				return strconv.FormatUint(uint64(a.ID), 10)
			}
			return ""
		},
	}
}

// UnixEndpoint returns the socket path of an export endpoint of the form
// unix:///path, and false for any other endpoint.
func UnixEndpoint(endpoint string) (string, bool) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "unix" {
		return "", false
	}
	return u.Path, true
}

// checkLocalSockets refuses a unix export endpoint that is not an absolute
// clean path alone, or that names no collector account, and a health socket
// beside a key it cannot be read with. Both need the platform to name a
// socket peer's account, and are refused where it cannot.
func (c *Config) checkLocalSockets() error {
	if err := c.checkUnixExport(); err != nil {
		return err
	}
	switch {
	case c.Health.Socket != "" && !peercred.Supported:
		return fmt.Errorf("health.socket: this platform cannot name a socket peer's account, so the socket would answer anyone")
	case c.Health.SocketUID.Set && c.Health.Socket == "":
		return fmt.Errorf("health.socket_uid: names who may read health.socket, which is not set")
	case c.Health.Socket != "" && c.Listener.Socket != "" && c.Resolve(c.Health.Socket) == c.Resolve(c.Listener.Socket):
		return fmt.Errorf("health.socket: it is listener.socket too")
	}
	return nil
}

func (c *Config) checkUnixExport() error {
	u, err := url.Parse(c.Export.Endpoint)
	if err != nil || u.Scheme != "unix" {
		if c.Export.CollectorUID.Set {
			return fmt.Errorf("export.collector_uid: only a unix:// endpoint's collector is checked by its account")
		}
		return nil
	}
	switch {
	case !socketOnly(c.Export.Endpoint, u):
		return fmt.Errorf("export.endpoint: a unix endpoint is unix:// followed by an absolute, clean socket path, and nothing else")
	case !peercred.Supported:
		return fmt.Errorf("export.endpoint: this platform cannot name a socket peer's account, so a unix endpoint's collector cannot be checked")
	case !c.Export.CollectorUID.Set:
		return fmt.Errorf("export.collector_uid: a unix endpoint needs the numeric user id its collector runs as; the credential is sent to no other account")
	case c.Export.AllowPlaintext:
		return fmt.Errorf("export.allow_plaintext: a unix endpoint crosses no network; leave it unset")
	}
	return nil
}

// socketOnly reports whether endpoint, parsed as u, is unix:// followed by an
// absolute, clean path and nothing else.
func socketOnly(endpoint string, u *url.URL) bool {
	return strings.HasPrefix(endpoint, "unix:///") && u.Host == "" && u.User == nil && u.RawQuery == "" &&
		u.Fragment == "" && u.Opaque == "" && path.IsAbs(u.Path) && path.Clean(u.Path) == u.Path
}

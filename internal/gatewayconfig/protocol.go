package gatewayconfig

import (
	"fmt"

	"github.com/guardana/control/internal/channel"
)

// ProtocolOf is the protocol a listener of the kind named speaks, as the
// adapter it starts names itself, so a reader takes the strength of a
// configured plane from the one protocol table and never from the kind. A
// kind this build starts no listener of is refused.
func ProtocolOf(listenerKind string) (string, error) {
	switch listenerKind {
	case ListenerStdio, ListenerStatelessHTTP, ListenerStatefulHTTP:
		return channel.ProtocolMCP, nil
	case ListenerEnforceAPI:
		return channel.ProtocolEnforce, nil
	}
	return "", fmt.Errorf("listener.kind: %q names no listener this build starts", listenerKind)
}

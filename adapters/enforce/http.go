package enforce

import (
	"context"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/internal/adapterkit"
	"github.com/guardana/control/internal/gateway"
)

// maxHeaderBytes bounds a request's headers: a run token and a handful of
// standard headers fit many times over.
const maxHeaderBytes = 1 << 14

type operation func(ctx context.Context, w http.ResponseWriter, r *http.Request, p Pipeline, run gateway.OpenedRun)

// Handler serves the three operations. Before Start, and once Shutdown
// began, every request with an accepted run token is answered
// ERROR_CODE_UNAVAILABLE. The path is judged first, then the method, then the
// run token; the body is read only after all three passed.
func (a *Adapter) Handler() http.Handler {
	ops := map[string]operation{PathAdmit: a.admit, PathComplete: a.complete, PathAbort: a.abort}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, ok := ops[r.URL.EscapedPath()]
		if !ok {
			a.refuse(w, enforcev1alpha1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, "this receiver serves /enforce/v1alpha1/admit, complete and abort", 0)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			a.refuseStatus(w, http.StatusMethodNotAllowed, enforcev1alpha1.ErrorCode_ERROR_CODE_MALFORMED, "every operation is a POST", 0)
			return
		}
		run, cause := a.resolve(r)
		if cause != "" {
			a.counts.runs.Count(cause)
			w.Header().Set("WWW-Authenticate", RunTokenHeader)
			a.refuse(w, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, "run token refused", 0)
			return
		}
		p := a.started()
		if p == nil || !a.flights.enter() {
			a.refuse(w, enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE, "the receiver is not serving requests", 0)
			return
		}
		defer a.flights.leave()
		op(r.Context(), w, r, p, run)
	})
}

// resolve returns the open run the request's one Run-Token names for the
// listener's identity at the adapter's clock, as adapterkit reads and
// resolves it for every adapter; a run the resolver answers for someone else
// is another identity's.
func (a *Adapter) resolve(r *http.Request) (gateway.OpenedRun, gateway.RunCause) {
	token, cause := adapterkit.HeaderToken(r.Header)
	if cause != "" {
		return gateway.OpenedRun{}, cause
	}
	who := a.who()
	run, cause := adapterkit.Resolve(r.Context(), a.cfg.Runs, token, who, a.cfg.Clock())
	switch {
	case cause != "":
		return gateway.OpenedRun{}, cause
	case run.Who != who:
		return gateway.OpenedRun{}, gateway.RunOtherIdentity
	}
	return run, ""
}

// who is the identity every run of this listener has to be for.
func (a *Adapter) who() gateway.RunIdentity {
	p := a.cfg.Identity.Principal
	return gateway.RunIdentity{TenantID: p.GetTenantId(), PrincipalType: p.GetType(), PrincipalID: p.GetId(), AgentID: a.cfg.Identity.Agent.GetId()}
}

// statusOf is the HTTP status each refusal is answered with.
func statusOf(code enforcev1alpha1.ErrorCode) int {
	switch code {
	case enforcev1alpha1.ErrorCode_ERROR_CODE_UNAUTHENTICATED:
		return http.StatusUnauthorized
	case enforcev1alpha1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_UNKNOWN:
		return http.StatusNotFound
	case enforcev1alpha1.ErrorCode_ERROR_CODE_HANDLE_SPENT, enforcev1alpha1.ErrorCode_ERROR_CODE_DUPLICATE_REQUEST:
		return http.StatusConflict
	case enforcev1alpha1.ErrorCode_ERROR_CODE_UNAVAILABLE:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}

// refuse answers the contract's Error body; ending is set only with
// HANDLE_SPENT. The message is fixed per refusal and never quotes the
// request, which may hold a request key or a token.
func (a *Adapter) refuse(w http.ResponseWriter, code enforcev1alpha1.ErrorCode, message string, ending enforcev1alpha1.Ending) {
	a.refuseStatus(w, statusOf(code), code, message, ending)
}

func (a *Adapter) refuseStatus(w http.ResponseWriter, status int, code enforcev1alpha1.ErrorCode, message string, ending enforcev1alpha1.Ending) {
	a.counts.refused(code)
	write(w, status, &enforcev1alpha1.Error{Code: code, Message: message, Ending: ending})
}

// write answers m as protojson. A message that will not marshal, which no
// message this package builds is, is answered as unavailable with no body
// rather than as a 200 with nothing in it.
func write(w http.ResponseWriter, status int, m proto.Message) {
	body, err := protojson.Marshal(m)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(body) // the status is sent; a client gone mid-body has nothing to read
}

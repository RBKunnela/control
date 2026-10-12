package enforce

import (
	"errors"
	"io"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	enforcev1alpha1 "github.com/guardana/control/api/gen/go/guardana/control/enforce/v1alpha1"
	"github.com/guardana/control/pkg/contract"
)

// maxRequestKey bounds a request key, whose characters are
// [A-Za-z0-9._-].
const maxRequestKey = 64

// errMalformed is every refusal of a request body. Its text is fixed and
// names no part of the request, which may hold a request key.
var errMalformed = errors.New("the body is not a strict, bounded request of this operation")

// readBody reads at most limit bytes of r and refuses one more.
func readBody(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errMalformed
	}
	return data, nil
}

// decodeAdmit, decodeComplete and decodeAbort read one request strictly: the
// protobuf JSON mapping with no member the message does not declare, then
// every bound and every value the operation needs.
func decodeAdmit(data []byte) (*enforcev1alpha1.AdmitRequest, error) {
	req := &enforcev1alpha1.AdmitRequest{}
	if err := unmarshal(data, req); err != nil {
		return nil, err
	}
	switch {
	case req.GetTool() == "" || len(req.GetTool()) > contract.MaxStringBytes,
		len(req.GetArguments()) > contract.MaxArgumentsBytes,
		len(req.GetTraceparent()) > contract.MaxStringBytes,
		!requestKey(req.GetRequestKey()):
		return nil, errMalformed
	}
	return req, nil
}

func decodeComplete(data []byte) (*enforcev1alpha1.CompleteRequest, error) {
	req := &enforcev1alpha1.CompleteRequest{}
	if err := unmarshal(data, req); err != nil {
		return nil, err
	}
	switch {
	case req.GetHandle() == "",
		req.GetStatus() == enforcev1alpha1.CompletionStatus_COMPLETION_STATUS_UNSPECIFIED || !declared(req.GetStatus()),
		len(req.GetSentArguments()) == 0 || len(req.GetSentArguments()) > contract.MaxArgumentsBytes,
		len(req.GetResultHash()) > contract.MaxStringBytes,
		len(req.GetSideEffectConfirmation()) > contract.MaxStringBytes,
		!validTime(req.GetStartedAt()), !validTime(req.GetEndedAt()):
		return nil, errMalformed
	}
	return req, nil
}

func decodeAbort(data []byte) (*enforcev1alpha1.AbortRequest, error) {
	req := &enforcev1alpha1.AbortRequest{}
	if err := unmarshal(data, req); err != nil {
		return nil, err
	}
	if req.GetHandle() == "" || req.GetCause() == enforcev1alpha1.AbortCause_ABORT_CAUSE_UNSPECIFIED || !declared(req.GetCause()) {
		return nil, errMalformed
	}
	return req, nil
}

func unmarshal(data []byte, m proto.Message) error {
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, m); err != nil {
		return errMalformed
	}
	return nil
}

// requestKey reports whether k is no key, or a key of 1 to 64 characters
// from [A-Za-z0-9._-].
func requestKey(k string) bool {
	if len(k) > maxRequestKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// validTime accepts an absent time or one the Timestamp type can hold.
func validTime(ts *timestamppb.Timestamp) bool {
	return ts == nil || ts.CheckValid() == nil
}

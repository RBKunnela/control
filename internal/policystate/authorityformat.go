package policystate

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
)

type authorityMarkerBody struct {
	SchemaVersion string   `json:"schema_version"`
	Kind          Kind     `json:"kind"`
	RosterIDs     []string `json:"roster_ids"`
}

type authorityFileBody struct {
	SchemaVersion string  `json:"schema_version"`
	RosterID      string  `json:"roster_id"`
	Serial        *int64  `json:"serial"`
	Digest        *string `json:"digest"`
}

func encodeAuthorityMarker(ids []string) ([]byte, error) {
	body, err := encode(authorityMarkerBody{SchemaVersion: SchemaVersion, Kind: KindAuthority, RosterIDs: ids})
	if err != nil {
		return nil, err
	}
	back, err := decodeAuthorityMarker(body)
	if err != nil || !slices.Equal(back, ids) {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

func decodeAuthorityMarker(raw []byte) ([]string, error) {
	members, err := readObject(raw, authorityMarkerMembers)
	if err != nil {
		return nil, err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return nil, fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return nil, err
	}
	if named, ok := strictjson.String(members["kind"]); !ok || Kind(named) != KindAuthority {
		return nil, fmt.Errorf("%w: kind", ErrMalformed)
	}
	return readIDs(members["roster_ids"], "roster_ids", MaxRosterIDs, ErrTooManyRosterIDs, checkRosterID)
}

func encodeAuthorityFile(f AuthorityFloor) ([]byte, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	out := authorityFileBody{SchemaVersion: SchemaVersion, RosterID: f.RosterID}
	if f.HasSerial() {
		out.Serial, out.Digest = &f.Serial, &f.Digest
	}
	body, err := encode(out)
	if err != nil {
		return nil, err
	}
	back, err := decodeAuthorityFile(body)
	if err != nil || back != f {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

// decodeAuthorityFile reads one authority floor file: serial and digest both
// null, or a serial and digest check takes.
func decodeAuthorityFile(raw []byte) (AuthorityFloor, error) {
	members, err := readObject(raw, authorityFileMembers)
	if err != nil {
		return AuthorityFloor{}, err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return AuthorityFloor{}, fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return AuthorityFloor{}, err
	}
	id, ok := strictjson.String(members["roster_id"])
	if !ok {
		return AuthorityFloor{}, fmt.Errorf("%w: roster_id is not a string", ErrMalformed)
	}
	f := AuthorityFloor{RosterID: id}
	serial, digest := members["serial"], members["digest"]
	switch {
	case isNull(serial) != isNull(digest):
		return AuthorityFloor{}, fmt.Errorf("%w: serial and digest are not both set or both null", ErrMalformed)
	case !isNull(serial):
		if f.Serial, err = strconv.ParseInt(string(serial), 10, 64); err != nil {
			return AuthorityFloor{}, fmt.Errorf("%w: serial is not an integer", ErrMalformed)
		}
		if f.Digest, ok = strictjson.String(digest); !ok {
			return AuthorityFloor{}, fmt.Errorf("%w: digest is not a string", ErrMalformed)
		}
		if f.Serial == 0 {
			return AuthorityFloor{}, fmt.Errorf("%w: serial 0", ErrMalformed)
		}
	}
	if err := f.check(); err != nil {
		return AuthorityFloor{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return f, nil
}

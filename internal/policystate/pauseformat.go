package policystate

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
)

type pauseMarkerBody struct {
	SchemaVersion string `json:"schema_version"`
	Kind          Kind   `json:"kind"`
	Tenant        string `json:"tenant"`
	Project       string `json:"project"`
}

type pauseFileBody struct {
	SchemaVersion string  `json:"schema_version"`
	Tenant        string  `json:"tenant"`
	Project       string  `json:"project"`
	Serial        *int64  `json:"serial"`
	Digest        *string `json:"digest"`
}

func encodePauseMarker(tenant, project string) ([]byte, error) {
	if err := checkPauseScope(tenant, project); err != nil {
		return nil, err
	}
	body, err := encode(pauseMarkerBody{SchemaVersion: SchemaVersion, Kind: KindPause, Tenant: tenant, Project: project})
	if err != nil {
		return nil, err
	}
	t, p, err := decodePauseMarker(body)
	if err != nil || t != tenant || p != project {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

func decodePauseMarker(raw []byte) (tenant, project string, err error) {
	members, err := readObject(raw, pauseMarkerMembers)
	if err != nil {
		return "", "", err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return "", "", fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return "", "", err
	}
	if named, ok := strictjson.String(members["kind"]); !ok || Kind(named) != KindPause {
		return "", "", fmt.Errorf("%w: kind", ErrMalformed)
	}
	tenant, okT := strictjson.String(members["tenant"])
	project, okP := strictjson.String(members["project"])
	if !okT || !okP {
		return "", "", fmt.Errorf("%w: tenant or project is not a string", ErrMalformed)
	}
	if err := checkPauseScope(tenant, project); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return tenant, project, nil
}

func encodePauseFile(f PauseFloor) ([]byte, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	out := pauseFileBody{SchemaVersion: SchemaVersion, Tenant: f.Tenant, Project: f.Project}
	if f.HasSerial() {
		out.Serial, out.Digest = &f.Serial, &f.Digest
	}
	body, err := encode(out)
	if err != nil {
		return nil, err
	}
	back, err := decodePauseFile(body)
	if err != nil || back != f {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

// decodePauseFile reads one pause floor file: serial and digest both null,
// or a serial and digest check takes.
func decodePauseFile(raw []byte) (PauseFloor, error) {
	members, err := readObject(raw, pauseFileMembers)
	if err != nil {
		return PauseFloor{}, err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return PauseFloor{}, fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return PauseFloor{}, err
	}
	tenant, okT := strictjson.String(members["tenant"])
	project, okP := strictjson.String(members["project"])
	if !okT || !okP {
		return PauseFloor{}, fmt.Errorf("%w: tenant or project is not a string", ErrMalformed)
	}
	f := PauseFloor{Tenant: tenant, Project: project}
	serial, digest := members["serial"], members["digest"]
	switch {
	case isNull(serial) != isNull(digest):
		return PauseFloor{}, fmt.Errorf("%w: serial and digest are not both set or both null", ErrMalformed)
	case !isNull(serial):
		var ok bool
		if f.Serial, err = strconv.ParseInt(string(serial), 10, 64); err != nil {
			return PauseFloor{}, fmt.Errorf("%w: serial is not an integer", ErrMalformed)
		}
		if f.Digest, ok = strictjson.String(digest); !ok {
			return PauseFloor{}, fmt.Errorf("%w: digest is not a string", ErrMalformed)
		}
		if f.Serial == 0 {
			return PauseFloor{}, fmt.Errorf("%w: serial 0", ErrMalformed)
		}
	}
	if err := f.check(); err != nil {
		return PauseFloor{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return f, nil
}

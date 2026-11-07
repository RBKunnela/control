package policystate

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/guardana/control/internal/canon"
	"github.com/guardana/control/internal/policy/strictjson"
)

type stopsMarkerBody struct {
	SchemaVersion string `json:"schema_version"`
	Kind          Kind   `json:"kind"`
	Tenant        string `json:"tenant"`
	Project       string `json:"project"`
}

type stopsFileBody struct {
	SchemaVersion string  `json:"schema_version"`
	Tenant        string  `json:"tenant"`
	Project       string  `json:"project"`
	Serial        *int64  `json:"serial"`
	Digest        *string `json:"digest"`
	Length        *int64  `json:"length"`
	Prefix        *string `json:"prefix"`
}

func encodeStopsMarker(tenant, project string) ([]byte, error) {
	if err := checkStopsScope(tenant, project); err != nil {
		return nil, err
	}
	body, err := encode(stopsMarkerBody{SchemaVersion: SchemaVersion, Kind: KindStops, Tenant: tenant, Project: project})
	if err != nil {
		return nil, err
	}
	t, p, err := decodeStopsMarker(body)
	if err != nil || t != tenant || p != project {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

func decodeStopsMarker(raw []byte) (tenant, project string, err error) {
	members, err := readObject(raw, stopsMarkerMembers)
	if err != nil {
		return "", "", err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return "", "", fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return "", "", err
	}
	if named, ok := strictjson.String(members["kind"]); !ok || Kind(named) != KindStops {
		return "", "", fmt.Errorf("%w: kind", ErrMalformed)
	}
	tenant, okT := strictjson.String(members["tenant"])
	project, okP := strictjson.String(members["project"])
	if !okT || !okP {
		return "", "", fmt.Errorf("%w: tenant or project is not a string", ErrMalformed)
	}
	if err := checkStopsScope(tenant, project); err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return tenant, project, nil
}

func encodeStopsFile(f StopsFloor) ([]byte, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	out := stopsFileBody{SchemaVersion: SchemaVersion, Tenant: f.Tenant, Project: f.Project}
	if f.HasSerial() {
		out.Serial, out.Digest, out.Length, out.Prefix = &f.Serial, &f.Digest, &f.Length, &f.Prefix
	}
	body, err := encode(out)
	if err != nil {
		return nil, err
	}
	back, err := decodeStopsFile(body)
	if err != nil || back != f {
		return nil, errors.Join(ErrUnwritable, err)
	}
	return body, nil
}

// decodeStopsFile reads one stop list floor file: serial, digest, length and
// prefix all null, or all set to what check takes.
func decodeStopsFile(raw []byte) (StopsFloor, error) {
	members, err := readObject(raw, stopsFileMembers)
	if err != nil {
		return StopsFloor{}, err
	}
	if _, err := canon.CanonicalizeJSON(raw); err != nil {
		return StopsFloor{}, fmt.Errorf("%w: not canonical JSON", ErrMalformed)
	}
	if err := checkSchemaVersion(members["schema_version"]); err != nil {
		return StopsFloor{}, err
	}
	tenant, okT := strictjson.String(members["tenant"])
	project, okP := strictjson.String(members["project"])
	if !okT || !okP {
		return StopsFloor{}, fmt.Errorf("%w: tenant or project is not a string", ErrMalformed)
	}
	f := StopsFloor{Tenant: tenant, Project: project}
	set := 0
	for _, name := range []string{"serial", "digest", "length", "prefix"} {
		if !isNull(members[name]) {
			set++
		}
	}
	switch set {
	case 0:
	case 4:
		if err := readStopsAt(members, &f); err != nil {
			return StopsFloor{}, err
		}
	default:
		return StopsFloor{}, fmt.Errorf("%w: serial, digest, length and prefix are not all set or all null", ErrMalformed)
	}
	if err := f.check(); err != nil {
		return StopsFloor{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return f, nil
}

// readStopsAt reads the serial, the head digest, the length and the prefix
// of a floor that holds a serial.
func readStopsAt(members strictjson.Object, f *StopsFloor) error {
	var err error
	if f.Serial, err = strconv.ParseInt(string(members["serial"]), 10, 64); err != nil {
		return fmt.Errorf("%w: serial is not an integer", ErrMalformed)
	}
	if f.Serial == 0 {
		return fmt.Errorf("%w: serial 0", ErrMalformed)
	}
	if f.Length, err = strconv.ParseInt(string(members["length"]), 10, 64); err != nil {
		return fmt.Errorf("%w: length is not an integer", ErrMalformed)
	}
	var okD, okP bool
	f.Digest, okD = strictjson.String(members["digest"])
	f.Prefix, okP = strictjson.String(members["prefix"])
	if !okD || !okP {
		return fmt.Errorf("%w: digest or prefix is not a string", ErrMalformed)
	}
	return nil
}

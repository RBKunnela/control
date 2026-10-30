package observe

import observev1 "github.com/guardana/control/api/gen/go/guardana/control/observe/v1alpha1"

// TrustOf reads a record's trust: unspecified, or a number this build does
// not declare, is self-reported.
func TrustOf(t observev1.Trust) observev1.Trust {
	if t == observev1.Trust_TRUST_UNSPECIFIED || declared(t) != nil {
		return observev1.Trust_TRUST_SELF_REPORTED
	}
	return t
}

// BasisOf reads a correlation's basis: unspecified or undeclared is none.
func BasisOf(b observev1.Basis) observev1.Basis {
	if b == observev1.Basis_BASIS_UNSPECIFIED || declared(b) != nil {
		return observev1.Basis_BASIS_NONE
	}
	return b
}

// StageOf reads a stage: an undeclared number is STAGE_UNSPECIFIED, which
// means unknown, never completed.
func StageOf(s observev1.Stage) observev1.Stage {
	if declared(s) != nil {
		return observev1.Stage_STAGE_UNSPECIFIED
	}
	return s
}

// SamplingOf reads a source's sampling: unspecified or undeclared is partial,
// so a missing record is never read as proof that nothing happened.
func SamplingOf(s observev1.Sampling) observev1.Sampling {
	if s == observev1.Sampling_SAMPLING_UNSPECIFIED || declared(s) != nil {
		return observev1.Sampling_SAMPLING_PARTIAL
	}
	return s
}

// CallerBasisOf reads a connection's caller basis: unspecified or undeclared
// is none.
func CallerBasisOf(b observev1.CallerBasis) observev1.CallerBasis {
	if b == observev1.CallerBasis_CALLER_BASIS_UNSPECIFIED || declared(b) != nil {
		return observev1.CallerBasis_CALLER_BASIS_NONE
	}
	return b
}

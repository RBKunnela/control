package reaction

import "fmt"

func (j *judging) liftLine(n int64, l LiftLine) error {
	if l.ThroughLine >= n {
		return ErrLiftOrder
	}
	target, err := liftedTarget(l)
	if err != nil {
		return err
	}
	key := liftKey{target, l.ThroughLine}
	if j.seen.lifts[key] {
		return ErrLiftAgain
	}
	switch j.route.format {
	case FormatV1Alpha1:
		if _, err := VerifyLiftLine(l, j.header, j.route); err != nil {
			return err
		}
	case FormatV1Alpha2Carry, FormatV1Alpha3:
		who, bound, err := verifySignedLiftLine(j.ctx, l, j.header, j.route)
		if err != nil {
			return err
		}
		j.seen.took(vouchedDoc{line: n, kind: VouchLift, env: l.Envelope, bound: bound, signer: who})
	default:
		return fmt.Errorf("%w: no route was read", ErrListRoute)
	}
	j.seen.lifts[key] = true
	j.seen.through[target] = max(j.seen.through[target], l.ThroughLine)
	j.lifted = true
	return nil
}

// liftedTarget is the scope and subject whose stops l ends: the run a 1.0
// or 2.0 lift line names, and the scope and subject of a 3.0 one, which
// names no run. A lift of a run ends no agent's or principal's stop, though
// that stop names the run its finding was about. Any other lift names
// nothing it could end and is refused.
func liftedTarget(l LiftLine) (Target, error) {
	switch {
	case l.Scope == "" && l.Subject == "" && l.RunID != "":
		return Target{ScopeRun, l.RunID}, nil
	case (l.Scope == ScopeRun || wider(l.Scope)) && l.Subject != "" && l.RunID == "":
		return Target{l.Scope, l.Subject}, nil
	}
	return Target{}, fmt.Errorf("%w: a lift of scope %q, subject %q and run %q names no stop it ends", ErrLineValue,
		l.Scope, l.Subject, l.RunID)
}

// VerifyLiftLine verifies l's envelope under r's lift key and ties the lift
// it signs to its place: the signed run and line are l's, the signed list id
// is h's, and the signed route digest is h's and r's. A lift is never read
// apart from the list and route it names.
func VerifyLiftLine(l LiftLine, h Header, r Route) (Lift, error) {
	if r.digest == "" {
		return Lift{}, fmt.Errorf("%w: no route was read", ErrListRoute)
	}
	if r.format != FormatV1Alpha1 {
		return Lift{}, fmt.Errorf("%w: the lifts of a route an operator signed are signed by operators", ErrLiftUnsigned)
	}
	signed, err := VerifyLift(l.Envelope, r.liftKey)
	if err != nil {
		return Lift{}, fmt.Errorf("%w: %w", ErrLiftUnsigned, err)
	}
	if signed.RunID != l.RunID || signed.ThroughLine != l.ThroughLine ||
		signed.ListID != h.ListID || signed.RouteDigest != h.RouteDigest || h.RouteDigest != r.digest {
		return Lift{}, ErrLiftMismatch
	}
	return signed, nil
}

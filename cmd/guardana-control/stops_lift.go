package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/policy/bundle"
	"github.com/guardana/control/internal/policykey"
	"github.com/guardana/control/internal/reaction"
	"github.com/guardana/control/internal/reaction/stopwrite"
)

type stopsLiftArgs struct {
	routeFlags
	key, run, agent, principal string
	through                    int64
}

// target is the scope and subject the flags name: exactly one of --run,
// --agent and --principal, which usable checks.
func (a stopsLiftArgs) target() reaction.Target {
	switch {
	case a.agent != "":
		return reaction.Target{Scope: reaction.ScopeAgent, Subject: a.agent}
	case a.principal != "":
		return reaction.Target{Scope: reaction.ScopePrincipal, Subject: a.principal}
	}
	return reaction.Target{Scope: reaction.ScopeRun, Subject: a.run}
}

// usable reports whether the flags name a route and its check, a key,
// exactly one of --run, --agent and --principal, --agent or --principal only
// under a route an operator signed, since a v1alpha1 route stops runs alone,
// and a --through above zero if given.
func (a stopsLiftArgs) usable(throughGiven bool) bool {
	named := 0
	for _, v := range []string{a.run, a.agent, a.principal} {
		if v != "" {
			named++
		}
	}
	return a.set() && a.key != "" && named == 1 && (a.run != "" || a.signed()) && (!throughGiven || a.through > 0)
}

// endsAStop refuses a lift of target through line through that would end
// none of list's stops, by the rule the writer and the judge hold it to.
func endsAStop(list reaction.List, target reaction.Target, through int64) error {
	if list.Ends(target, through) {
		return nil
	}
	return fmt.Errorf("%s %s has no stop through line %d for a lift to end", target.Scope, oneLine(target.Subject), through)
}

func stopsLiftFlags(command string, out io.Writer) (*flag.FlagSet, *stopsLiftArgs) {
	flags := commandFlags(command, out)
	a := &stopsLiftArgs{}
	a.declare(flags)
	flags.StringVar(&a.key, "key", "", "the private key file of the route's lift key, or the operator's for a v1alpha3 route")
	flags.StringVar(&a.run, "run", "", "the opened run whose stops the lift ends")
	flags.StringVar(&a.agent, "agent", "", "the agent whose stops the lift ends, under a v1alpha3 route")
	flags.StringVar(&a.principal, "principal", "", "the principal whose stops the lift ends, under a v1alpha3 route")
	flags.Int64Var(&a.through, "through", 0, "the last line the lift ends; the list's last complete line when left out")
	return flags, a
}

func stopsLiftFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := stopsLiftFlags(command, out)
	return flags
}

// stopsLiftCommand checks its own arguments for key text, as signCommand
// does.
func stopsLiftCommand(args []string, stdout, stderr io.Writer) int {
	if err := policykey.CheckArguments(args); err != nil {
		return usageError(stderr, stopsLiftName, err.Error())
	}
	flags, a := stopsLiftFlags(stopsLiftName, io.Discard)
	err := flags.Parse(args)
	throughGiven := false
	flags.Visit(func(f *flag.Flag) { throughGiven = throughGiven || f.Name == "through" })
	if err != nil || flags.NArg() != 1 || !a.usable(throughGiven) {
		return usageError(stderr, stopsLiftName,
			"takes --route with --public-key or with --roster and --root-key, --key, exactly one of --run, --agent and --principal, "+
				"--agent or --principal only with --roster, a --through above zero if any, then the stops directory")
	}
	if a.signed() {
		return stopsLiftSigned(*a, flags.Arg(0), time.Now(), stdout, stderr)
	}
	return stopsLift(*a, flags.Arg(0), time.Now(), stdout, stderr)
}

// stopsLift refuses in a fixed order and writes nothing on any refusal: the
// route, the key, which must be the route's lift key, the list, a lift that
// would end no stop, then the lift as the plane's judge reads it.
func stopsLift(a stopsLiftArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.liftable(dir, &rosterNote{w: stderr, command: stopsLiftName})
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	key, err := policykey.ReadPrivate(a.key)
	if err != nil {
		return fail(stderr, stopsLiftName, fmt.Errorf("--key: %w", err))
	}
	defer clear(key)
	if pub, _ := key.Public().(ed25519.PublicKey); !bytes.Equal(pub, route.LiftKey()) {
		return fail(stderr, stopsLiftName, errors.New("--key: its public half is not the route's lift_public_key"))
	}
	list, _, err := liftableList(dir, route, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	through := a.through
	if through == 0 {
		through = list.Usage().Lines
	}
	if err := endsAStop(list, a.target(), through); err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	lift := reaction.Lift{Version: reaction.LiftVersion, ListID: list.Header().ListID, RouteDigest: route.Digest(),
		RunID: a.run, ThroughLine: through}
	env, err := reaction.SignLift(lift, key)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	n, err := stopwrite.AppendLift(ctx, dir, route, reaction.LiftLine{RunID: a.run, ThroughLine: through, Envelope: env}, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	return emit(stdout, stderr, stopsLiftName,
		[]string{fmt.Sprintf("lift line %d run %s through line %d", n, oneLine(a.run), through)}, dir)
}

// stopsLiftSigned refuses in a fixed order and writes nothing on any
// refusal: the route, the list, whose header and lifts are judged through
// the roster before anything is signed, a lift that would end no stop of
// the run, agent or principal named, the key, then the lift as the plane's
// judge reads it. The lift names the
// list's head, so it never verifies against another list. It says on
// standard error what it signed.
func stopsLiftSigned(a stopsLiftArgs, dir string, now time.Time, stdout, stderr io.Writer) int {
	route, err := a.liftable(dir, &rosterNote{w: stderr, command: stopsLiftName})
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	list, _, err := liftableList(dir, route, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	through := a.through
	if through == 0 {
		through = list.Usage().Lines
	}
	target := a.target()
	if err := endsAStop(list, target, through); err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	key, release, err := readOperatorKey(a.key)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	defer release()
	lift := reaction.SignedLiftV3{
		KeyID: policykey.KeyID(publicHalf(key)), PlaneID: route.PlaneID(), ListHead: list.Header().Signed.Digest,
		Scope: target.Scope, Subject: target.Subject, ThroughLine: through,
		TenantID: route.TenantID(), Project: route.ProjectID(), File: route.Plane().ListFile,
	}
	body, err := lift.Payload()
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	sig, err := bundle.SignBytesAs(reaction.SignedLiftPayloadType, body, key)
	if err != nil {
		return fail(stderr, stopsLiftName, fmt.Errorf("--key: %w", err))
	}
	env := reaction.Envelope{PayloadType: reaction.SignedLiftPayloadType, Payload: body,
		Signatures: []reaction.Signature{{KeyID: lift.KeyID, Signature: sig}}}
	ctx, cancel := context.WithTimeout(context.Background(), stopsLockWait)
	defer cancel()
	n, err := stopwrite.AppendLift(ctx, dir, route,
		reaction.LiftLine{Scope: target.Scope, Subject: target.Subject, ThroughLine: through, Envelope: env}, now)
	if err != nil {
		return fail(stderr, stopsLiftName, err)
	}
	writeLine(stderr, fmt.Sprintf("%s: %s: signed lift of %s %s through line %d of list head %s for plane %s tenant %s project %s of %s",
		brand.CLI, stopsLiftName, target.Scope, oneLine(target.Subject), through, lift.ListHead, oneLine(lift.PlaneID),
		oneLine(lift.TenantID), oneLine(lift.Project), oneLine(lift.File)))
	return emit(stdout, stderr, stopsLiftName,
		[]string{fmt.Sprintf("lift line %d %s %s through line %d", n, target.Scope, oneLine(target.Subject), through)}, dir)
}

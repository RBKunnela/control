package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/guardana/control/internal/brand"
	"github.com/guardana/control/internal/pause"
)

// initFlags is what pause init is told: nothing for an unsigned file, and
// the key, the plane's id, tenant and project and the first serial for a
// signed one.
type initFlags struct {
	key, plane, tenant, project *string
	serial                      *int64
}

// planeFlag declares --plane-id, the id of the plane a signed pause file is
// for.
func planeFlag(flags *flag.FlagSet) *string {
	return flags.String("plane-id", "", "the plane's plane_id, which a signed pause file is for")
}

func pauseInitFlags(command string, out io.Writer) (*flag.FlagSet, initFlags) {
	flags := commandFlags(command, out)
	v := initFlags{key: keyFlag(flags), plane: planeFlag(flags)}
	v.tenant = flags.String("tenant", "", "the plane's tenant_id, which a signed pause file is for")
	v.project = flags.String("project", "", "the plane's project_id, which a signed pause file is for")
	v.serial = flags.Int64("serial", 1, "the signed file's first serial, above the plane's pause floor")
	return flags, v
}

func pauseInitFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := pauseInitFlags(command, out)
	return flags
}

// pauseInitCommand writes a pause file that pauses nothing: unsigned, or
// with --key signed.
func pauseInitCommand(args []string, stdout, stderr io.Writer) int {
	flags, v := pauseInitFlags(pauseInitName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		return usageError(stderr, pauseInitName, "takes the pause file, with every flag before it")
	}
	given := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { given[f.Name] = true })
	ctx, cancel := context.WithTimeout(context.Background(), pauseLockWait)
	defer cancel()
	path := flags.Arg(0)
	if !given["key"] {
		if given["plane-id"] || given["tenant"] || given["project"] || given["serial"] {
			return usageError(stderr, pauseInitName, "--plane-id, --tenant, --project and --serial make a signed pause file, with --key")
		}
		if err := pause.Init(ctx, path); err != nil {
			return fail(stderr, pauseInitName, err)
		}
		return report(stdout, stderr, pauseInitName, "created "+oneLine(path)+", which pauses nothing")
	}
	return pauseInitSigned(ctx, path, v, stdout, stderr)
}

// pauseInitSigned is pause init with --key: a file signed for the plane's
// id, tenant and project at --serial, which it says before it signs.
func pauseInitSigned(ctx context.Context, path string, v initFlags, stdout, stderr io.Writer) int {
	if *v.plane == "" || *v.tenant == "" || *v.project == "" {
		return usageError(stderr, pauseInitName, "a signed pause file names the plane's --plane-id, --tenant and --project")
	}
	signer, release, err := pauseSigner(*v.key, "", "", nil)
	if err != nil {
		return fail(stderr, pauseInitName, err)
	}
	defer release()
	h := pause.Header{KeyID: signer.KeyID, PlaneID: *v.plane, Tenant: *v.tenant, Project: *v.project, Serial: *v.serial}
	writeLine(stderr, fmt.Sprintf("%s: %s: signing serial %d for plane %s tenant %s project %s, 0 entry(ies)", brand.CLI, pauseInitName,
		h.Serial, oneLine(h.PlaneID), oneLine(h.Tenant), oneLine(h.Project)))
	if err := pause.InitSigned(ctx, path, h, signer); err != nil {
		return fail(stderr, pauseInitName, err)
	}
	return report(stdout, stderr, pauseInitName, fmt.Sprintf("created %s, which pauses nothing, signed by key %s for plane %s at serial %d",
		oneLine(path), signer.KeyID, oneLine(h.PlaneID), h.Serial))
}

// resignFlags is what pause sign is told: a signed write's flags and the
// plane the file is signed for.
type resignFlags struct {
	sign  pauseSignFlags
	plane *string
}

func pauseResignFlags(command string, out io.Writer) (*flag.FlagSet, resignFlags) {
	flags := commandFlags(command, out)
	return flags, resignFlags{sign: pauseSignFlagsOf(flags), plane: planeFlag(flags)}
}

func pauseSignFlagSet(command string, out io.Writer) *flag.FlagSet {
	flags, _ := pauseResignFlags(command, out)
	return flags
}

// pauseSignCommand signs the entries of a signed pause file again, as the
// current version for --plane-id at the next serial, once the roster vouches
// for the file it starts from. It is how a version 3 file, which a plane
// refuses, is carried with every pause it holds; a file already of the
// current version for the same plane is signed again at the next serial, and
// one of another plane is refused.
func pauseSignCommand(args []string, stdout, stderr io.Writer) int {
	flags, v := pauseResignFlags(pauseSignName, stderr)
	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() != 1 {
		return usageError(stderr, pauseSignName, "takes the pause file, with every flag before it")
	}
	if *v.sign.key == "" || *v.plane == "" {
		return usageError(stderr, pauseSignName, "names --key, --roster, --root-key and the plane's --plane-id")
	}
	if problem := v.sign.problem(); problem != "" {
		return usageError(stderr, pauseSignName, problem)
	}
	path := flags.Arg(0)
	var signed pause.SignedDocument
	err := writePause(pauseSignName, v.sign, stderr, func(ctx context.Context, signer *pause.Signer) (pause.SignedDocument, error) {
		var err error
		signed, err = pause.Resign(ctx, path, *v.plane, *signer)
		return signed, err
	})
	if err != nil {
		return fail(stderr, pauseSignName, err)
	}
	return report(stdout, stderr, pauseSignName, fmt.Sprintf("signed %s again as version %s for plane %s at serial %d, %d entry(ies) kept",
		oneLine(path), pause.SignedVersion, oneLine(signed.PlaneID), signed.Serial, len(signed.Entries)))
}

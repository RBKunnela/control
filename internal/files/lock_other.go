//go:build !linux && !darwin

package files

import (
	"context"
	"os"
)

func openJudged(*os.Root, string) (*os.File, error) { return nil, ErrNoExchange }

func lockFile(context.Context, *os.File) error { return ErrNoExchange }

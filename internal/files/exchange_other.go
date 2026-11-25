//go:build !linux && !darwin

package files

import "os"

func exchange(*os.File, string, string) error { return ErrNoExchange }

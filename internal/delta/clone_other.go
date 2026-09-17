//go:build !linux && !darwin

package delta

import "errors"

func reflink(src, dst string) error {
	return errors.New("reflink not supported on this platform")
}

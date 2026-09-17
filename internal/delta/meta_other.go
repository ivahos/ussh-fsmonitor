//go:build !linux && !darwin

package delta

func copyXattrs(src, dst string, logf func(string, ...any)) {}

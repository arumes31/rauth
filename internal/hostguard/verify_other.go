//go:build !linux

package hostguard

func Verify(string, string, string) error            { return ErrGuard }
func Execute(string, string, string, []string) error { return ErrGuard }

func Describe(int) (map[string]string, error) { return nil, ErrGuard }

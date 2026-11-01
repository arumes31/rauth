//go:build !linux

package clusterconfig

func readPrivate(string, int64) ([]byte, error) { return nil, ErrUnsupported }
func validateMount(Config) error                { return ErrUnsupported }

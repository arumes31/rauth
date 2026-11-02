//go:build !linux

package clusterconfig

import "os"

func readPrivate(string, int64) ([]byte, error) { return nil, ErrUnsupported }
func validateMount(Config) error                { return ErrUnsupported }

func validateCacheRoot(Config) error { return ErrUnsupported }

func validateSourceDirectory(Config) error   { return ErrUnsupported }
func openGeoSource(Config) (*os.File, error) { return nil, ErrUnsupported }

func validateEventDirectory(Config) error { return ErrUnsupported }

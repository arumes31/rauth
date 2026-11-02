//go:build !linux

package eventspool

import "os"

func openDirectory(string) (*os.File, error)                                { return nil, ErrUnsafe }
func openFile(*os.File, string, string, int, os.FileMode) (*os.File, error) { return nil, ErrUnsafe }

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"rauth/internal/hostguard"
)

func main() {
	witness := flag.String("witness", "/guard/identity.json", "read-only tmpfs witness")
	uuid := flag.String("uuid", "", "expected host filesystem UUID")
	role := flag.String("role", "", "expected protected role")
	inspect := flag.Int("inspect-fd", -1, "describe physical identity of an inherited descriptor")
	verify := flag.Bool("verify-only", false, "verify without executing a command")
	flag.Parse()
	var err error
	if *inspect >= 0 && !*verify && *uuid == "" && *role == "" && len(flag.Args()) == 0 {
		var identity map[string]string
		identity, err = hostguard.Describe(*inspect)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(identity)
		}
	} else if *inspect != -1 {
		err = hostguard.ErrGuard
	} else if *verify && len(flag.Args()) == 0 {
		err = hostguard.Verify(*witness, *uuid, *role)
	} else if !*verify {
		err = hostguard.Execute(*witness, *uuid, *role, flag.Args())
	} else {
		err = hostguard.ErrGuard
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "host storage guard verification failed")
		os.Exit(1)
	}
}

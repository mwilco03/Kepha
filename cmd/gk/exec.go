package main

import "os/exec"

// newCommand creates an exec.Cmd. Factored out for testability.
func newCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

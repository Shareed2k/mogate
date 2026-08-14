package main

import (
	"reflect"
	"testing"
)

// TestPlanKubeAgent pins the pure decision behind kube-agent's --no-redirect
// flag: with no-redirect, the nftables redirector and the incoming capture it
// feeds must be excluded and only the egress task scheduled; by default both
// run. This must fail if someone re-adds the redirector to the no-redirect
// path.
func TestPlanKubeAgent(t *testing.T) {
	t.Parallel()

	t.Run("no-redirect excludes the redirector and incoming capture", func(t *testing.T) {
		t.Parallel()
		plan := planKubeAgent(true)
		if plan.UsesRedirector {
			t.Fatal("planKubeAgent(true).UsesRedirector = true, want false: no-redirect must not touch nftables")
		}
		want := []string{"remote egress"}
		if !reflect.DeepEqual(plan.TaskNames, want) {
			t.Fatalf("planKubeAgent(true).TaskNames = %v, want %v", plan.TaskNames, want)
		}
	})

	t.Run("default installs the redirector and captures incoming traffic", func(t *testing.T) {
		t.Parallel()
		plan := planKubeAgent(false)
		if !plan.UsesRedirector {
			t.Fatal("planKubeAgent(false).UsesRedirector = false, want true")
		}
		want := []string{"incoming capture", "remote egress"}
		if !reflect.DeepEqual(plan.TaskNames, want) {
			t.Fatalf("planKubeAgent(false).TaskNames = %v, want %v", plan.TaskNames, want)
		}
	})
}

// TestNewKubeAgentCommandNoRedirectFlag checks the --no-redirect flag is wired
// up on the command and defaults to false (the current, privileged behavior).
func TestNewKubeAgentCommandNoRedirectFlag(t *testing.T) {
	t.Parallel()
	flag := newKubeAgentCommand().Flags().Lookup("no-redirect")
	if flag == nil {
		t.Fatal("kube-agent command missing --no-redirect flag")
	}
	if flag.Value.Type() != "bool" {
		t.Fatalf("--no-redirect type = %q, want bool", flag.Value.Type())
	}
	if flag.DefValue != "false" {
		t.Fatalf("--no-redirect default = %q, want false", flag.DefValue)
	}
}

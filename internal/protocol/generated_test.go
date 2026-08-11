package protocol_test

import (
	"os/exec"
	"testing"
)

func TestGeneratedContractIsCurrent(t *testing.T) {
	command := exec.Command("go", "run", "../cmd/protocolgen", "-check")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated Wire Contract is stale: %v\n%s", err, output)
	}
}

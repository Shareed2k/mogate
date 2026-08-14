//go:build darwin

package local

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden regenerates the committed .slice golden vectors from the current
// chooseSlice output (`go test ./pkg/local -run TestSIPChooseSliceParity
// -update`). The goldens are committed and normally read-only; -update is the
// single guarded path that rewrites them after an intentional fixture change.
var updateGolden = flag.Bool("update", false, "regenerate the golden .slice vectors from the current chooseSlice output")

// sipFixtureDir holds the committed Mach-O fixtures and their golden .slice
// vectors. The same directory is reached from the injector cgo parity test via
// ../pkg/local/testdata/sip, so the C thinner is asserted byte-identical to the
// exact bytes recorded here.
const sipFixtureDir = "testdata/sip"

// sipParityCase pairs a committed fixture with what chooseSlice must do with it.
// When golden is set, chooseSlice must succeed with wantArch and its chosen-slice
// bytes must equal the golden file; when golden is empty, chooseSlice must fail,
// and wantErr (if set) is asserted via errors.Is.
type sipParityCase struct {
	fixture  string
	golden   string
	wantArch sipArch
	wantErr  error
}

// sipParityCases enumerates the Task E1 vectors. fat x86_64+arm64e and thin
// x86_64 are injectable (x86_64 under Rosetta, since arm64e enforces pointer
// authentication); thin arm64e has no injectable slice; a shebang script is not
// a Mach-O at all.
var sipParityCases = []sipParityCase{
	{fixture: "fat_x64_arm64e", golden: "fat_x64_arm64e.slice", wantArch: sipArchRosetta},
	{fixture: "thin_x64", golden: "thin_x64.slice", wantArch: sipArchRosetta},
	{fixture: "thin_arm64e", wantErr: ErrNoInjectableSlice},
	{fixture: "script.sh"}, // not a Mach-O: chooseSlice returns a (non-sentinel) parse error
}

// TestSIPChooseSliceParity records the Go chooseSlice output for each committed
// fixture to a golden .slice vector (under -update) and asserts the current
// output still equals it byte-for-byte. The same goldens are compared against
// the C mg_sip_choose_slice in injector/sip_cgo_test.go, so the two thinners
// cannot silently drift on well-formed input.
func TestSIPChooseSliceParity(t *testing.T) {
	for _, tc := range sipParityCases {
		t.Run(tc.fixture, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(sipFixtureDir, tc.fixture))
			if err != nil {
				t.Fatalf("read fixture %s: %v", tc.fixture, err)
			}

			slice, arch, err := chooseSlice(data)

			if tc.golden == "" {
				// chooseSlice must refuse this fixture (arm64e-only, or non-Mach-O).
				if err == nil {
					t.Fatalf("chooseSlice(%s) = arch %v, %d bytes; want an error", tc.fixture, arch, len(slice))
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("chooseSlice(%s) err = %v, want %v", tc.fixture, err, tc.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("chooseSlice(%s): %v", tc.fixture, err)
			}
			if arch != tc.wantArch {
				t.Fatalf("chooseSlice(%s) arch = %v, want %v", tc.fixture, arch, tc.wantArch)
			}

			goldenPath := filepath.Join(sipFixtureDir, tc.golden)
			if *updateGolden {
				if err := os.WriteFile(goldenPath, slice, 0o644); err != nil {
					t.Fatalf("write golden %s: %v", goldenPath, err)
				}
				t.Logf("updated golden %s (%d bytes)", goldenPath, len(slice))
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s (regenerate via `go test ./pkg/local -run TestSIPChooseSliceParity -update`): %v", goldenPath, err)
			}
			if !bytes.Equal(slice, want) {
				t.Fatalf("chooseSlice(%s) chose %d bytes that differ from golden %s (%d bytes)",
					tc.fixture, len(slice), tc.golden, len(want))
			}
		})
	}
}

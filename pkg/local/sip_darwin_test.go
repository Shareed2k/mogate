//go:build darwin

package local

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// copyFile copies src to dst, failing the test on any error. The copy is a
// plain data copy: it does not preserve extended attributes, code-signature
// validity, or the SF_RESTRICTED file flag (cp semantics on macOS).
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %q: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		t.Fatalf("create %q: %v", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %q -> %q: %v", src, dst, err)
	}
}

func TestNeedsSIPPatch(t *testing.T) {
	t.Run("SF_RESTRICTED system binary is restricted", func(t *testing.T) {
		// /usr/bin/curl carries the SF_RESTRICTED file flag on macOS.
		got, err := needsSIPPatch("/usr/bin/curl")
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		if !got {
			t.Fatal("expected /usr/bin/curl to be restricted")
		}
	})

	t.Run("a plain unsigned copy is not restricted", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "curl")
		copyFile(t, "/usr/bin/curl", dst) // cp drops SF_RESTRICTED; still platform cdhash, but no CS RESTRICT/RUNTIME flags
		got, err := needsSIPPatch(dst)
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		// A bare copy of curl has flags=0x0 and no SF_RESTRICTED -> our
		// file+CS-flag detection returns false. (Platform-binary cdhash is not
		// file-detectable; the copy is what we ultimately run anyway.)
		if got {
			t.Fatal("expected a plain copy to be un-restricted by file+CS-flag detection")
		}
	})

	t.Run("non-existent path errors", func(t *testing.T) {
		if _, err := needsSIPPatch(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})

	t.Run("non-mach-o is not restricted", func(t *testing.T) {
		dir := t.TempDir()
		p := filepath.Join(dir, "hello.txt")
		if err := os.WriteFile(p, []byte("hello\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := needsSIPPatch(p)
		if err != nil {
			t.Fatalf("needsSIPPatch: %v", err)
		}
		if got {
			t.Fatal("expected a text file to be un-restricted")
		}
	})
}

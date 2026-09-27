package testutil

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func Deb(t *testing.T, dir, name, version, arch, compression, extra string) string {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: Test <test@example.com>\n%sDescription: test package\n long description\n .\n more\n", name, version, arch, extra)

	var ctl bytes.Buffer
	var w io.WriteCloser
	switch compression {
	case "gz":
		w = gzip.NewWriter(&ctl)
	case "xz":
		xw, err := xz.NewWriter(&ctl)
		if err != nil {
			t.Fatal(err)
		}
		w = xw
	case "zst":
		zw, err := zstd.NewWriter(&ctl)
		if err != nil {
			t.Fatal(err)
		}
		w = zw
	default:
		t.Fatalf("unknown compression %s", compression)
	}
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(control))}); err != nil {
		t.Fatal(err)
	}
	tw.Write([]byte(control))
	tw.Close()
	w.Close()

	var data bytes.Buffer
	gw := gzip.NewWriter(&data)
	dtw := tar.NewWriter(gw)
	payload := []byte(name + " " + version + " " + arch + "\n")
	dtw.WriteHeader(&tar.Header{Name: "./usr/share/doc/" + name + "/payload", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(payload))})
	dtw.Write(payload)
	dtw.Close()
	gw.Close()

	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	member := func(n string, content []byte) {
		fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", n, 0, 0, 0, "100644", len(content))
		b.Write(content)
		if len(content)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	member("debian-binary", []byte("2.0\n"))
	member("control.tar."+compression, ctl.Bytes())
	member("data.tar.gz", data.Bytes())

	path := filepath.Join(dir, strings.NewReplacer("/", "_", ":", "_").Replace(fmt.Sprintf("%s_%s_%s.deb", name, version, arch)))
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

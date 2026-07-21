package server

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // Test fixtures produce Git-format SHA-1 pack trailers.
	"encoding/binary"
	"fmt"
	"testing"
)

func TestScanReceivePackInspectsCompressedCommitAndBlob(t *testing.T) {
	for name, object := range map[string]packTestObject{
		"blob":   {typ: 3, data: []byte("github_pat_abcdefghijklmnopqrstuvwxyz123456")},
		"commit": {typ: 1, data: []byte("tree 0000000000000000000000000000000000000000\n\nsecret github_pat_abcdefghijklmnopqrstuvwxyz123456\n")},
	} {
		t.Run(name, func(t *testing.T) {
			finding, err := scanReceivePack(testReceivePack(t, []packTestObject{object}))
			if err != nil || finding == nil || finding.Code != "github_token" {
				t.Fatalf("scan = %#v, %v", finding, err)
			}
		})
	}
}

func TestScanReceivePackResolvesOFSAndREFDeltas(t *testing.T) {
	base := []byte("benign original blob")
	delta := append(deltaVarint(len(base)), deltaVarint(len(base))...)
	delta = append(delta, 0x91, 0, 20) // copy offset 0, explicit size
	for _, kind := range []string{"ofs", "ref"} {
		t.Run(kind, func(t *testing.T) {
			objects := []packTestObject{{typ: 3, data: base}}
			if kind == "ofs" {
				objects = append(objects, packTestObject{typ: 6, data: delta, baseOffset: 12})
			} else {
				objects = append(objects, packTestObject{typ: 7, data: delta, baseID: gitObjectID(3, base)})
			}
			finding, err := scanReceivePack(testReceivePack(t, objects))
			if err != nil || finding != nil {
				t.Fatalf("scan = %#v, %v", finding, err)
			}
		})
	}
}

func TestScanReceivePackInspectsAnnotatedTagsAndTreeEntryNames(t *testing.T) {
	secret := "github_pat_abcdefghijklmnopqrstuvwxyz123456"
	objects := map[string]packTestObject{
		"annotated tag message": {typ: 4, data: annotatedTag("release", "message "+secret)},
		"annotated tag header":  {typ: 4, data: annotatedTag(secret, "clean message")},
		"tree entry name":       {typ: 2, data: treeObject(secret)},
	}
	for name, object := range objects {
		t.Run(name, func(t *testing.T) {
			finding, err := scanReceivePack(testReceivePack(t, []packTestObject{object}))
			if err != nil || finding == nil || finding.Code != "github_token" {
				t.Fatalf("scan = %#v, %v", finding, err)
			}
		})
	}
	for _, typ := range []byte{2, 4} {
		for _, kind := range []string{"ofs", "ref"} {
			t.Run(fmt.Sprintf("delta %d %s", typ, kind), func(t *testing.T) {
				base := semanticCleanObject(typ)
				target := semanticSecretObject(typ, secret)
				objects := []packTestObject{{typ: typ, data: base}}
				delta := literalDelta(base, target)
				if kind == "ofs" {
					objects = append(objects, packTestObject{typ: 6, data: delta, baseOffset: 12})
				} else {
					objects = append(objects, packTestObject{typ: 7, data: delta, baseID: gitObjectID(typ, base)})
				}
				finding, err := scanReceivePack(testReceivePack(t, objects))
				if err != nil || finding == nil || finding.Code != "github_token" {
					t.Fatalf("scan = %#v, %v", finding, err)
				}
			})
		}
	}
	for _, object := range []packTestObject{{typ: 4, data: annotatedTag("release", "clean message")}, {typ: 2, data: treeObject("clean-name")}} {
		finding, err := scanReceivePack(testReceivePack(t, []packTestObject{object}))
		if err != nil || finding != nil {
			t.Fatalf("clean semantic object scan = %#v, %v", finding, err)
		}
	}
}

func TestScanReceivePackFailsClosedOnMalformedAndLimits(t *testing.T) {
	valid := testReceivePack(t, []packTestObject{{typ: 3, data: []byte("benign")}})
	for _, body := range [][]byte{valid[:len(valid)-21], append(valid[:len(valid)-20], 0x80, 0x00)} {
		if _, err := scanReceivePack(body); err == nil {
			t.Fatal("malformed pack accepted")
		}
	}
	big := bytes.Repeat([]byte("x"), maxPackObjectSize+1)
	if _, err := scanReceivePack(testReceivePack(t, []packTestObject{{typ: 3, data: big}})); err == nil {
		t.Fatal("expanded object limit accepted")
	}
	for _, object := range []packTestObject{
		{typ: 2, data: []byte("100644 missing-nul")},
		{typ: 4, data: []byte("object 0000000000000000000000000000000000000000\ntype commit\n\nmissing tagger")},
	} {
		if _, err := scanReceivePack(testReceivePack(t, []packTestObject{object})); err == nil {
			t.Fatal("malformed semantic object accepted")
		}
	}
}

type packTestObject struct {
	typ        byte
	data       []byte
	baseOffset int
	baseID     [20]byte
}

func testReceivePack(t *testing.T, objects []packTestObject) []byte {
	t.Helper()
	payload := "0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/agent/test\x00report-status\n"
	prefix := []byte(fmt.Sprintf("%04x%s0000", len(payload)+4, payload))
	var pack bytes.Buffer
	pack.WriteString("PACK")
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], 2)
	if len(objects) > maxPackObjects {
		t.Fatal("too many fixture objects")
	}
	binary.BigEndian.PutUint32(header[4:], uint32(len(objects))) //nolint:gosec // Bounds check above makes the conversion safe.
	pack.Write(header[:])
	for _, o := range objects {
		offset := pack.Len()
		declared := len(o.data)
		if o.typ == 6 || o.typ == 7 {
			_, n, err := readDeltaVarint(o.data)
			if err != nil {
				t.Fatal(err)
			}
			result, _, err := readDeltaVarint(o.data[n:])
			if err != nil {
				t.Fatal(err)
			}
			declared = int(result)
		}
		pack.Write(packHeader(o.typ, declared))
		if o.typ == 6 { // test packs keep the base at offset 12, distance is current offset - 12.
			d := offset - o.baseOffset
			if d >= 128 {
				t.Fatal("test OFS delta distance too large")
			}
			pack.WriteByte(byte(d)) //nolint:gosec // Bound check above constrains d to one byte.
		}
		if o.typ == 7 {
			pack.Write(o.baseID[:])
		}
		var compressed bytes.Buffer
		zw := zlib.NewWriter(&compressed)
		if _, err := zw.Write(o.data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		pack.Write(compressed.Bytes())
	}
	sum := sha1.Sum(pack.Bytes()) //nolint:gosec // Git pack trailer algorithm is SHA-1.
	pack.Write(sum[:])
	return append(prefix, pack.Bytes()...)
}

func packHeader(typ byte, size int) []byte {
	first := (typ << 4) | byte(size&15)
	size >>= 4
	out := []byte{first}
	if size > 0 {
		out[0] |= 0x80
	}
	for size > 0 {
		b := byte(size & 0x7f)
		size >>= 7
		if size > 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

func deltaVarint(n int) []byte {
	out := []byte{}
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func annotatedTag(name, message string) []byte {
	return []byte("object 0000000000000000000000000000000000000000\ntype commit\ntag " + name + "\ntagger Test <test@example.invalid> 0 +0000\n\n" + message)
}

func treeObject(name string) []byte {
	return append([]byte("100644 "+name+"\x00"), bytes.Repeat([]byte{0}, sha1.Size)...)
}

func semanticCleanObject(typ byte) []byte {
	if typ == 2 {
		return treeObject("clean-name")
	}
	return annotatedTag("release", "clean message")
}

func semanticSecretObject(typ byte, secret string) []byte {
	if typ == 2 {
		return treeObject(secret)
	}
	return annotatedTag("release", "message "+secret)
}

func literalDelta(base, target []byte) []byte {
	delta := append(deltaVarint(len(base)), deltaVarint(len(target))...)
	for len(target) > 0 {
		n := len(target)
		if n > 127 {
			n = 127
		}
		delta = append(delta, byte(n))
		delta = append(delta, target[:n]...)
		target = target[n:]
	}
	return delta
}

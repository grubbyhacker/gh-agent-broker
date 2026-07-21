package server

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1" //nolint:gosec // Git pack format mandates SHA-1 object IDs and trailer checksums.
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"gh-agent-broker/internal/securityscan"
)

// These limits deliberately sit below the request bound. They ensure malformed
// or adversarial packs cannot turn inspection into an allocation or CPU sink.
const (
	maxPackObjects    = 4096
	maxPackObjectSize = 4 << 20
	maxPackTotalSize  = 16 << 20
	maxDeltaDepth     = 32
)

type packedObject struct {
	typ     byte
	size    int64
	data    []byte
	baseOff int
	baseID  [20]byte
	hasRef  bool
	offset  int
}

// scanReceivePack parses the pkt-line command prefix and a complete SHA-1 pack
// stream. It scans resolved semantic payloads (commits, blobs, annotated tags,
// and tree entry names), never compressed transport bytes. Unsupported/thin/corrupt packs are rejected by returning an
// error so callers fail closed before forwarding.
func scanReceivePack(body []byte) (*securityscan.Finding, error) {
	prefix, _, err := readReceivePackCommandPrefix(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) < len(prefix)+12+20 || !bytes.Equal(body[len(prefix):len(prefix)+4], []byte("PACK")) {
		return nil, errors.New("missing complete pack stream")
	}
	pack := body[len(prefix):]
	checksum := sha1.Sum(pack[:len(pack)-sha1.Size]) //nolint:gosec // Git pack checksum algorithm is SHA-1.
	if !bytes.Equal(checksum[:], pack[len(pack)-sha1.Size:]) {
		return nil, errors.New("pack checksum mismatch")
	}
	version, count := binary.BigEndian.Uint32(pack[4:8]), binary.BigEndian.Uint32(pack[8:12])
	if (version != 2 && version != 3) || count == 0 || count > maxPackObjects {
		return nil, errors.New("invalid pack header")
	}
	objects := make([]packedObject, 0, count)
	byOffset := make(map[int]int, count)
	byID := make(map[[20]byte]int, count)
	pos := 12
	var total int64
	for i := uint32(0); i < count; i++ {
		if pos >= len(pack)-20 {
			return nil, errors.New("truncated pack object")
		}
		off := pos
		typ, size, n, err := readPackObjectHeader(pack[pos:])
		if err != nil || size > maxPackObjectSize {
			return nil, errors.New("invalid pack object header")
		}
		pos += n
		o := packedObject{typ: typ, size: size, offset: off, baseOff: -1}
		if typ == 6 {
			base, consumed, e := readOFSDeltaOffset(pack[pos:], off)
			if e != nil || base < 12 {
				return nil, errors.New("invalid OFS_DELTA base")
			}
			o.baseOff, pos = base, pos+consumed
		} else if typ == 7 {
			if len(pack)-pos < sha1.Size+20 {
				return nil, errors.New("truncated REF_DELTA base")
			}
			copy(o.baseID[:], pack[pos:pos+sha1.Size])
			o.hasRef = true
			pos += sha1.Size
		} else if typ < 1 || typ > 4 {
			return nil, errors.New("unsupported pack object type")
		}
		data, consumed, e := inflatePackObject(pack[pos:len(pack)-20], maxPackObjectSize)
		if e != nil {
			return nil, e
		}
		if typ >= 1 && typ <= 4 && int64(len(data)) != size {
			return nil, errors.New("pack object size mismatch")
		}
		pos += consumed
		o.data = data
		total += int64(len(data))
		if total > maxPackTotalSize {
			return nil, errors.New("pack expanded size limit")
		}
		byOffset[off] = len(objects)
		objects = append(objects, o)
		if typ >= 1 && typ <= 4 {
			byID[gitObjectID(typ, data)] = len(objects) - 1
		}
	}
	if pos != len(pack)-20 {
		return nil, errors.New("trailing or truncated pack data")
	}
	for i := range objects {
		typ, data, e := resolvePackObject(i, objects, byOffset, byID, 0)
		if e != nil {
			return nil, e
		}
		if finding, scanErr := scanPackSemanticObject(typ, data); scanErr != nil {
			return nil, scanErr
		} else if finding != nil {
			return finding, nil
		}
	}
	return nil, nil //nolint:nilnil // A nil finding is the successful scan result.
}

func scanPackSemanticObject(typ byte, data []byte) (*securityscan.Finding, error) {
	switch typ {
	case 1:
		return securityscan.Reader("pack_commit", bytes.NewReader(data), int64(maxPackObjectSize)), nil
	case 2:
		return scanPackTree(data)
	case 3:
		return securityscan.Reader("pack_blob", bytes.NewReader(data), int64(maxPackObjectSize)), nil
	case 4:
		if err := validateAnnotatedTag(data); err != nil {
			return nil, err
		}
		return securityscan.Reader("pack_tag", bytes.NewReader(data), int64(maxPackObjectSize)), nil
	default:
		return nil, errors.New("unsupported resolved pack object type")
	}
}

func scanPackTree(data []byte) (*securityscan.Finding, error) {
	for pos := 0; pos < len(data); {
		space := bytes.IndexByte(data[pos:], ' ')
		if space <= 0 {
			return nil, errors.New("malformed tree mode")
		}
		mode := data[pos : pos+space]
		if !validTreeMode(mode) {
			return nil, errors.New("malformed tree mode")
		}
		pos += space + 1
		nul := bytes.IndexByte(data[pos:], 0)
		if nul <= 0 {
			return nil, errors.New("malformed tree name")
		}
		name := data[pos : pos+nul]
		if bytes.IndexByte(name, '/') >= 0 {
			return nil, errors.New("malformed tree name")
		}
		if finding := securityscan.Reader("pack_tree_entry_name", bytes.NewReader(name), int64(len(name))); finding != nil {
			return finding, nil
		}
		pos += nul + 1
		if len(data)-pos < sha1.Size {
			return nil, errors.New("truncated tree object id")
		}
		pos += sha1.Size
	}
	return nil, nil //nolint:nilnil // A nil finding is the successful scan result.
}

func validTreeMode(mode []byte) bool {
	switch string(mode) {
	case "40000", "100644", "100755", "120000", "160000":
		return true
	default:
		return false
	}
}

func validateAnnotatedTag(data []byte) error {
	separator := bytes.Index(data, []byte("\n\n"))
	if separator < 0 {
		return errors.New("malformed annotated tag")
	}
	headers := bytes.Split(data[:separator], []byte("\n"))
	if len(headers) != 4 || !bytes.HasPrefix(headers[0], []byte("object ")) {
		return errors.New("malformed annotated tag")
	}
	if len(headers[0]) != len("object ")+40 || !bytes.HasPrefix(headers[1], []byte("type ")) || !bytes.HasPrefix(headers[2], []byte("tag ")) || !bytes.HasPrefix(headers[3], []byte("tagger ")) {
		return errors.New("malformed annotated tag")
	}
	for _, b := range headers[0][len("object "):] {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return errors.New("malformed annotated tag")
		}
	}
	if len(headers[1]) == len("type ") || !validTagTargetType(headers[1][len("type "):]) || len(headers[2]) == len("tag ") || len(headers[3]) == len("tagger ") {
		return errors.New("malformed annotated tag")
	}
	return nil
}

func validTagTargetType(value []byte) bool {
	return bytes.Equal(value, []byte("commit")) || bytes.Equal(value, []byte("tree")) || bytes.Equal(value, []byte("blob")) || bytes.Equal(value, []byte("tag"))
}

func readPackObjectHeader(b []byte) (byte, int64, int, error) {
	if len(b) == 0 {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}
	c, shift, size, n := b[0], uint(4), int64(b[0]&15), 1
	typ := (c >> 4) & 7
	for c&0x80 != 0 {
		if n >= len(b) || shift > 56 {
			return 0, 0, 0, errors.New("object header overflow")
		}
		c = b[n]
		n++
		size |= int64(c&0x7f) << shift
		shift += 7
	}
	return typ, size, n, nil
}

func readOFSDeltaOffset(b []byte, objectOffset int) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v, n := int(b[0]&0x7f), 1
	for b[n-1]&0x80 != 0 {
		if n >= len(b) || n > 8 {
			return 0, 0, errors.New("ofs delta overflow")
		}
		v = ((v + 1) << 7) + int(b[n]&0x7f)
		n++
	}
	if v <= 0 || v >= objectOffset {
		return 0, 0, errors.New("invalid ofs delta")
	}
	return objectOffset - v, n, nil
}

func inflatePackObject(b []byte, limit int64) ([]byte, int, error) {
	r := bytes.NewReader(b)
	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, 0, fmt.Errorf("zlib: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(zr, limit+1))
	closeErr := zr.Close()
	if err != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, 0, errors.New("invalid zlib object")
	}
	return data, len(b) - r.Len(), nil
}

func resolvePackObject(i int, objects []packedObject, byOffset map[int]int, byID map[[20]byte]int, depth int) (byte, []byte, error) {
	if depth > maxDeltaDepth || i < 0 || i >= len(objects) {
		return 0, nil, errors.New("delta depth or reference invalid")
	}
	o := objects[i]
	if o.typ >= 1 && o.typ <= 4 {
		return o.typ, o.data, nil
	}
	var (
		base int
		ok   bool
	)
	if o.hasRef {
		base, ok = byID[o.baseID]
	} else {
		base, ok = byOffset[o.baseOff]
	}
	if !ok {
		return 0, nil, errors.New("thin delta rejected")
	}
	typ, data, err := resolvePackObject(base, objects, byOffset, byID, depth+1)
	if err != nil {
		return 0, nil, err
	}
	out, err := applyDelta(data, o.data)
	if err != nil || int64(len(out)) != o.size || len(out) > maxPackObjectSize {
		return 0, nil, errors.New("invalid delta")
	}
	return typ, out, nil
}

func applyDelta(base, delta []byte) ([]byte, error) {
	pos := 0
	baseSize, n, err := readDeltaVarint(delta[pos:])
	if err != nil || int(baseSize) != len(base) {
		return nil, errors.New("delta base size")
	}
	pos += n
	resultSize, n, err := readDeltaVarint(delta[pos:])
	if err != nil || resultSize > maxPackObjectSize {
		return nil, errors.New("delta result size")
	}
	pos += n
	out := make([]byte, 0, resultSize)
	for pos < len(delta) {
		op := delta[pos]
		pos++
		if op&0x80 != 0 {
			off, size := 0, 0
			for bit, shift := byte(1), uint(0); bit <= 0x08; bit, shift = bit<<1, shift+8 {
				if op&bit != 0 {
					if pos >= len(delta) {
						return nil, io.ErrUnexpectedEOF
					}
					off |= int(delta[pos]) << shift
					pos++
				}
			}
			for bit, shift := byte(0x10), uint(0); bit <= 0x40; bit, shift = bit<<1, shift+8 {
				if op&bit != 0 {
					if pos >= len(delta) {
						return nil, io.ErrUnexpectedEOF
					}
					size |= int(delta[pos]) << shift
					pos++
				}
			}
			if size == 0 {
				size = 0x10000
			}
			if off < 0 || size < 0 || off > len(base)-size || len(out) > maxPackObjectSize-size {
				return nil, errors.New("delta copy range")
			}
			out = append(out, base[off:off+size]...)
		} else if op != 0 {
			if int(op) > len(delta)-pos || len(out) > maxPackObjectSize-int(op) {
				return nil, errors.New("delta insert range")
			}
			out = append(out, delta[pos:pos+int(op)]...)
			pos += int(op)
		} else {
			return nil, errors.New("delta reserved opcode")
		}
	}
	if int64(len(out)) != resultSize {
		return nil, errors.New("delta result mismatch")
	}
	return out, nil
}

func readDeltaVarint(b []byte) (int64, int, error) {
	var v int64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= int64(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errors.New("delta varint")
}

func gitObjectID(typ byte, data []byte) [20]byte {
	return sha1.Sum(append([]byte(fmt.Sprintf("%s %d\x00", packTypeName(typ), len(data))), data...)) //nolint:gosec // Git object IDs are SHA-1 by format definition.
}

func packTypeName(typ byte) string {
	return map[byte]string{1: "commit", 2: "tree", 3: "blob", 4: "tag"}[typ]
}

package ftdc

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	TypeMetadata         int32 = 0
	TypeMetricChunk      int32 = 1
	TypePeriodicMetadata int32 = 2
)

type RawDocument struct {
	Offset int
	Bytes  []byte
	Doc    bson.D
}

type MetricChunk struct {
	RefBSON      []byte
	MetricsCount uint32
	DeltaCount   uint32
	DeltaStream  []byte
}

// maxDocument bounds a BSON document (16 MB, with room for FTDC chunks).
const maxDocument = 64 << 20

// ErrTruncated reports a file that ends inside a document, as the
// metrics.interim file of a running mongod can.
var ErrTruncated = errors.New("truncated FTDC document")

// Reader reads FTDC documents one at a time.
type Reader struct {
	r      io.Reader
	offset int
}

func NewReader(r io.Reader) *Reader { return &Reader{r: r} }

// Next returns the next document, io.EOF at a clean end, or an error that
// wraps ErrTruncated when the file ends inside a document.
func (rd *Reader) Next() (RawDocument, error) {
	var head [4]byte
	n, err := io.ReadFull(rd.r, head[:])
	if err == io.EOF {
		return RawDocument{}, io.EOF
	}
	if err != nil {
		return RawDocument{}, fmt.Errorf("%w at offset %d (%d trailing bytes)", ErrTruncated, rd.offset, n)
	}
	docLen := int(int32(binary.LittleEndian.Uint32(head[:])))
	if docLen == 0 {
		return RawDocument{}, io.EOF // zero padding after the last document
	}
	if docLen < 5 || docLen > maxDocument {
		return RawDocument{}, fmt.Errorf("invalid FTDC document length %d at offset %d", docLen, rd.offset)
	}
	raw := make([]byte, docLen)
	copy(raw, head[:])
	if _, err := io.ReadFull(rd.r, raw[4:]); err != nil {
		return RawDocument{}, fmt.Errorf("%w at offset %d", ErrTruncated, rd.offset)
	}
	var doc bson.D
	if err := bson.Unmarshal(raw, &doc); err != nil {
		return RawDocument{}, fmt.Errorf("decode FTDC document at offset %d: %w", rd.offset, err)
	}
	d := RawDocument{Offset: rd.offset, Bytes: raw, Doc: doc}
	rd.offset += docLen
	return d, nil
}

// Iterate decodes every document of data; it returns the documents read
// before an error.
func Iterate(data []byte) ([]RawDocument, error) {
	rd := NewReader(bytes.NewReader(data))
	var docs []RawDocument
	for {
		d, err := rd.Next()
		if err == io.EOF {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		docs = append(docs, d)
	}
}

// Sniff reports whether head (the start of a file) is an FTDC file: a BSON
// document whose first field is "_id" (a date), as every FTDC document has.
func Sniff(head []byte) bool {
	if len(head) < 10 {
		return false
	}
	docLen := int(int32(binary.LittleEndian.Uint32(head[:4])))
	if docLen < 10 || docLen > maxDocument {
		return false
	}
	return head[4] == 0x09 && bytes.HasPrefix(head[5:], []byte("_id\x00"))
}

func Type(doc bson.D) (int32, bool) {
	for _, elem := range doc {
		if elem.Key != "type" {
			continue
		}
		switch v := elem.Value.(type) {
		case int32:
			return v, true
		case int64:
			return int32(v), true
		case int:
			return int32(v), true
		}
	}
	return 0, false
}

// ID returns the "_id" date of an FTDC document: the time of the first sample
// of a metric chunk, or of a metadata document.
func ID(doc bson.D) (time.Time, bool) {
	for _, elem := range doc {
		if elem.Key == "_id" {
			if d, ok := elem.Value.(primitive.DateTime); ok {
				return d.Time(), true
			}
			return time.Time{}, false
		}
	}
	return time.Time{}, false
}

func BinaryField(doc bson.D, key string) (primitive.Binary, bool) {
	for _, elem := range doc {
		if elem.Key == key {
			v, ok := elem.Value.(primitive.Binary)
			return v, ok
		}
	}
	return primitive.Binary{}, false
}

func DocField(doc bson.D, key string) (bson.D, bool) {
	for _, elem := range doc {
		if elem.Key == key {
			v, ok := elem.Value.(bson.D)
			return v, ok
		}
	}
	return nil, false
}

func ReplaceField(doc bson.D, key string, value any) bson.D {
	out := make(bson.D, len(doc))
	copy(out, doc)
	for i := range out {
		if out[i].Key == key {
			out[i].Value = value
			return out
		}
	}
	return append(out, bson.E{Key: key, Value: value})
}

func DecompressMetricChunk(data []byte) (MetricChunk, error) {
	if len(data) < 4 {
		return MetricChunk{}, fmt.Errorf("chunk too short")
	}
	uncompressedLen := binary.LittleEndian.Uint32(data[:4])
	zr, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return MetricChunk{}, err
	}
	uncompressed, err := io.ReadAll(zr)
	closeErr := zr.Close()
	if err != nil {
		return MetricChunk{}, err
	}
	if closeErr != nil {
		return MetricChunk{}, closeErr
	}
	if uint32(len(uncompressed)) != uncompressedLen {
		return MetricChunk{}, fmt.Errorf("chunk length mismatch: header=%d actual=%d", uncompressedLen, len(uncompressed))
	}
	if len(uncompressed) < 12 {
		return MetricChunk{}, fmt.Errorf("uncompressed chunk too short")
	}
	refLen := int(int32(binary.LittleEndian.Uint32(uncompressed[:4])))
	if refLen < 5 || refLen+8 > len(uncompressed) {
		return MetricChunk{}, fmt.Errorf("invalid reference BSON length %d", refLen)
	}
	pos := refLen
	return MetricChunk{RefBSON: append([]byte(nil), uncompressed[:refLen]...), MetricsCount: binary.LittleEndian.Uint32(uncompressed[pos : pos+4]), DeltaCount: binary.LittleEndian.Uint32(uncompressed[pos+4 : pos+8]), DeltaStream: append([]byte(nil), uncompressed[pos+8:]...)}, nil
}

func RecompressMetricChunk(chunk MetricChunk) ([]byte, error) {
	payload := make([]byte, 0, len(chunk.RefBSON)+8+len(chunk.DeltaStream))
	payload = append(payload, chunk.RefBSON...)
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:4], chunk.MetricsCount)
	binary.LittleEndian.PutUint32(buf[4:], chunk.DeltaCount)
	payload = append(payload, buf[:]...)
	payload = append(payload, chunk.DeltaStream...)
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(payload); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	out := make([]byte, 4, 4+compressed.Len())
	binary.LittleEndian.PutUint32(out, uint32(len(payload)))
	out = append(out, compressed.Bytes()...)
	return out, nil
}

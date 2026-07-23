package ftdc

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"

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

func Iterate(data []byte) ([]RawDocument, error) {
	var docs []RawDocument
	for pos := 0; pos+4 <= len(data); {
		docLen := int(int32(binary.LittleEndian.Uint32(data[pos : pos+4])))
		if docLen <= 0 {
			break
		}
		if docLen < 5 || pos+docLen > len(data) {
			return docs, fmt.Errorf("truncated FTDC document at offset %d", pos)
		}
		raw := data[pos : pos+docLen]
		var doc bson.D
		if err := bson.Unmarshal(raw, &doc); err != nil {
			return docs, fmt.Errorf("decode FTDC document at offset %d: %w", pos, err)
		}
		docs = append(docs, RawDocument{Offset: pos, Bytes: append([]byte(nil), raw...), Doc: doc})
		pos += docLen
	}
	return docs, nil
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

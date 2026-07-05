// Package blobcodec provides transparent zstd compression for SQLite BLOB columns.
//
// Encode compresses with zstd at maximum compression (writes are write-once per
// module extraction, so throughput matters less than ratio). Decode auto-detects
// compressed vs uncompressed data by checking the zstd magic number, so rows
// written before compression was introduced continue to read correctly.
package blobcodec

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// zstd frame magic number (little-endian 0xFD2FB528).
var zstdMagic = [4]byte{0x28, 0xb5, 0x2f, 0xfd}

var (
	enc *zstd.Encoder
	dec *zstd.Decoder
)

func init() {
	var err error
	enc, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		panic("blobcodec: init encoder: " + err.Error())
	}
	dec, err = zstd.NewReader(nil)
	if err != nil {
		panic("blobcodec: init decoder: " + err.Error())
	}
}

// Encode compresses data with zstd. Safe for concurrent use.
func Encode(data []byte) []byte {
	return enc.EncodeAll(data, make([]byte, 0, len(data)/4))
}

// Decode returns decompressed data if data is zstd-compressed, or data unchanged
// if it is raw (backward-compatibility path for rows written before).
// Safe for concurrent use.
func Decode(data []byte) ([]byte, error) {
	if len(data) < 4 || [4]byte(data[:4]) != zstdMagic {
		return data, nil
	}
	out, err := dec.DecodeAll(data, make([]byte, 0, len(data)*4))
	if err != nil {
		return nil, fmt.Errorf("decompressing blob: %w", err)
	}
	return out, nil
}

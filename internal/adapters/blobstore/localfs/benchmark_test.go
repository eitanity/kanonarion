package localfs_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobstore/localfs"
)

// BenchmarkPut measures streaming blob storage for various payload sizes.
// Memory use should be ~32 KB regardless of size (bounded by io.Copy buffer).
func BenchmarkPut(b *testing.B) {
	sizes := []int{
		1 << 10,  // 1 KB
		1 << 20,  // 1 MB
		5 << 20,  // 5 MB
		50 << 20, // 50 MB
	}
	ctx := context.Background()
	for _, sz := range sizes {
		payload := bytes.Repeat([]byte("x"), sz)
		b.Run(fmt.Sprintf("size=%s", humanBytes(sz)), func(b *testing.B) {
			dir := b.TempDir()
			store := localfs.New(dir)
			b.SetBytes(int64(sz))
			b.ResetTimer()
			for range b.N {
				if _, err := store.Put(ctx, bytes.NewReader(payload)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

package localfs_test

import (
	"strconv"

	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"

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
			for i := range b.N {
				// A distinct identity per iteration: an identity already held is a
				// no-op, which would benchmark the existence check rather than the
				// write.
				identity := ports.BlobIdentity{
					Kind: ports.BlobKindZip,
					Hash: fetchtest.H1(strconv.Itoa(i)),
				}
				if err := store.Put(ctx, identity, bytes.NewReader(payload)); err != nil {
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

package godoc_test

import (
	"context"
	"testing"
	"testing/fstest"
)

func BenchmarkExtractor_Extract(b *testing.B) {
	fsys := fstest.MapFS{
		"client.go": &fstest.MapFile{
			Data: []byte(`package mypkg

// Client calls the remote service.
type Client struct {
	// Timeout is the request timeout.
	Timeout int
}

// Do sends a request.
func (c *Client) Do() error { return nil }
`),
		},
	}
	ext := makeExtractor()
	c := coord(b)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, err := ext.Extract(ctx, fsys, c)
		if err != nil {
			b.Fatal(err)
		}
	}
}

package govulncheck

type limitWriter struct {
	limit int
	buf   []byte
}

func (w *limitWriter) Write(p []byte) (n int, err error) {
	if len(w.buf) < w.limit {
		toCopy := len(p)
		if len(w.buf)+toCopy > w.limit {
			toCopy = w.limit - len(w.buf)
		}
		w.buf = append(w.buf, p[:toCopy]...)
	}
	return len(p), nil
}
func (w *limitWriter) String() string {
	return string(w.buf)
}
func (w *limitWriter) Len() int {
	return len(w.buf)
}

package storage

// ResetRegistry empties the process-wide registry between tests.
func ResetRegistry() { resetRegistry() }

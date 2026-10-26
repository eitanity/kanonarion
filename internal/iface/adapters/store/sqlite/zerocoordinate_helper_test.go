package sqlite_test

import "code.eitanity.com/kanonarion/internal/coordinate"

// zeroCoordinate is the value the constructors cannot produce and Go cannot
// forbid: the empty coordinate, which names no module.
func zeroCoordinate() coordinate.ModuleCoordinate { return coordinate.ModuleCoordinate{} }

// Package ports defines the interfaces the iface application layer requires
// from the outside world.
//
// The iface context reuses BlobStore, FactStore, and Clock from the fetch
// ports package. Those are not re-declared here; the application layer imports
// them directly from fetch/ports.
package ports

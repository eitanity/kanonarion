// Package application contains the fetch use cases.
//
// - FetchModuleUseCase orchestrates a single fetch: resolve the version via
// the proxy, download the module zip, cross-verify it against the Go
// checksum database and (unless skipped) the upstream VCS, persist the
// zip to the blob store, and write a FactRecord with its
// VerificationStatus. The aggregate it produces is fetch/domain's
// FactRecord.
// - QueryFetchUseCase provides read-only access to stored FactRecords.
//
// The layer depends only on fetch/domain and fetch/ports — it has no
// knowledge of HTTP, SQLite, filesystems, or git mechanics. All timestamps
// come from an injected Clock so fetches are reproducible under a fixed
// clock; verification logic lives here (the domain only defines the status
// enum).
package application

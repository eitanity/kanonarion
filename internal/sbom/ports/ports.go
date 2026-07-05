package ports

import (
	"context"
	"errors"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensedomain "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// ErrSBOMNotFound is returned when a requested SBOM record does not exist.
var ErrSBOMNotFound = errors.New("sbom record not found")

// GeneratorMetadata provides identity information for an SBOM generator.
type GeneratorMetadata struct {
	Name    string
	Version string
}

// SBOMGenerator is the port for producing SBOM documents from walk facts.
type SBOMGenerator interface {
	// Generate produces an SBOMRecord from the supplied walk, licence, and
	// optional vulnerability data. The resulting Content is deterministic:
	// identical inputs always produce byte-identical output.
	Generate(
		ctx context.Context,
		walk walkdomain.WalkRecord,
		licenses map[fetchdomain.ModuleCoordinate]licensedomain.LicenseRecord,
		vulnerabilities []vulndomain.VulnerabilityRecord,
		req GenerateRequest,
	) (domain.SBOMRecord, error)

	// GeneratorMetadata returns identity information for this generator.
	GeneratorMetadata() GeneratorMetadata
}

// GenerateRequest carries the caller-supplied parameters for a single generation.
type GenerateRequest struct {
	WalkScanRunID   *string
	Format          domain.SBOMFormat
	PipelineVersion string
	Operator        string
}

// SBOMStore is the port for persisting and retrieving SBOM records.
type SBOMStore interface {
	// PutSBOMRecord persists an SBOM record. Idempotent on ID.
	PutSBOMRecord(ctx context.Context, r domain.SBOMRecord) error

	// GetSBOMRecord retrieves an SBOM record by ID.
	// Returns ErrSBOMNotFound when not present.
	GetSBOMRecord(ctx context.Context, id string) (domain.SBOMRecord, error)

	// ListSBOMRecords returns all SBOM records for a walk, most recent first.
	ListSBOMRecords(ctx context.Context, walkID string) ([]domain.SBOMRecord, error)

	// FindSBOMRecord looks up a cached record by the cache key
	// (walkID, walkScanRunID, format, pipelineVersion).
	// Returns (zero, false, nil) when not found.
	FindSBOMRecord(
		ctx context.Context,
		walkID string,
		walkScanRunID *string,
		format domain.SBOMFormat,
		pipelineVersion string,
	) (domain.SBOMRecord, bool, error)
}

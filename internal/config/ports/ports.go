// Package ports defines the interfaces the config bounded context exposes.
package ports

import (
	"context"

	"github.com/eitanity/kanonarion/internal/config/domain"
)

// ConfigStore loads a Config from a versioned source.
// The default implementation is adapters/store/yaml.
// Future adapters may load from etcd, Vault, or other remote sources.
type ConfigStore interface {
	LoadConfig(ctx context.Context) (domain.Config, error)
}

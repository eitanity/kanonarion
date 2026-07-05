package domain

// Classify assigns a Tier to a detected setting by name lookup in the
// versioned taxonomy. A setting the taxonomy does not know returns
// TierUnknown — per the absence of a classification is a distinct,
// surfaced state, never silently the benign (green) answer. The policy
// mapping (config context) is responsible for failing safe on TierUnknown.
//
// Classification is by setting *name* only: the value (e.g. tlsrsakex=1 vs
// =0) does not change the risk tier — the presence of a deprecated-behaviour
// knob is itself the finding. Whether the setting is Applied is orthogonal
// and recorded separately on the Setting.
func Classify(name string) Tier {
	if t, ok := taxonomy.tiers[name]; ok {
		return t
	}
	return TierUnknown
}

// PipelineFingerprint is the cache key suffix that makes a taxonomy revision
// part of pipeline identity: re-running an unchanged scan under a newer
// taxonomy must not return a stale cached classification. The store keys on
// it so a taxonomy bump transparently re-classifies.
func PipelineFingerprint() string {
	return PipelineVersion + "+tax." + TaxonomyVersion()
}

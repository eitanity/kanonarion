// Package fetch adapts the fetch context's FetchModuleUseCase to the vuln
// context's ports.ModuleFetcher.
//
// It exists so the vuln application layer can pre-fetch modules missing from
// the fact store without importing fetch/application directly: the cross-
// context dependency is confined to this adapter (the anti-corruption layer),
// keeping the vuln application pure against ports.ModuleFetcher.
package fetch

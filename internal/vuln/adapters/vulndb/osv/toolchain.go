package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// SnapshotToolchainAdvisories reads what a stored snapshot says under its
// toolchain key: the ids its index lists there, and for each id the affected
// ranges and retraction stamp its own ID/<id>.json record carries.
//
// Both halves come out of the one stored zip, so the whole judgment costs a
// single local read of a snapshot the store already holds and never a request.
// That is what lets it be derived at report time on every run, including runs
// that are entirely offline.
//
// A snapshot whose index has no toolchain key returns KeyPresent false rather
// than an error: it is a database generation that cannot judge a toolchain, and
// the caller reports that rather than treating it as a clear.
func (d *Database) SnapshotToolchainAdvisories(ctx context.Context, identity domain.DatabaseSnapshot) (domain.ToolchainAdvisorySet, error) {
	zr, err := d.openStoredSnapshot(ctx, identity)
	if err != nil {
		return domain.ToolchainAdvisorySet{}, err
	}

	files := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		files[f.Name] = f
	}

	indexFile, ok := files["index/modules.json"]
	if !ok {
		return domain.ToolchainAdvisorySet{}, fmt.Errorf("stored snapshot %s@%s has no index/modules.json", identity.Source(), identity.Version())
	}
	indexData, err := readZipFile(indexFile, maxModulesIndexBytes)
	if err != nil {
		return domain.ToolchainAdvisorySet{}, err
	}
	ids, present, err := toolchainAdvisoryIDs(indexData)
	if err != nil {
		return domain.ToolchainAdvisorySet{}, err
	}
	if !present {
		return domain.ToolchainAdvisorySet{}, nil
	}

	set := domain.ToolchainAdvisorySet{KeyPresent: true, Advisories: make([]domain.ToolchainAdvisory, 0, len(ids))}
	for _, id := range ids {
		adv, aerr := readSnapshotAdvisory(files, id)
		if aerr != nil {
			// The index named this advisory, so it covers some toolchain version;
			// only the record stating which one is unreadable. Reporting the id with
			// no range would make it cover everything, and dropping it would make a
			// listed advisory vanish, so the snapshot is refused as an evidence base
			// and the caller says the toolchain could not be judged against it.
			return domain.ToolchainAdvisorySet{}, fmt.Errorf("stored snapshot %s@%s lists toolchain advisory %s but its record is unreadable: %w",
				identity.Source(), identity.Version(), id, aerr)
		}
		set.Advisories = append(set.Advisories, adv)
	}
	return set, nil
}

// toolchainAdvisoryIDs pulls the toolchain key's advisory ids out of a decoded
// index/modules.json, reporting separately whether the key was there at all.
func toolchainAdvisoryIDs(data []byte) (ids []string, present bool, err error) {
	var index []struct {
		Path  string `json:"path"`
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, false, fmt.Errorf("unmarshal modules index: %w", err)
	}
	for _, m := range index {
		if m.Path != domain.ToolchainModulePath {
			continue
		}
		present = true
		for _, v := range m.Vulns {
			if v.ID != "" {
				ids = append(ids, v.ID)
			}
		}
	}
	return ids, present, nil
}

// readSnapshotAdvisory decodes one ID/<id>.json out of the stored snapshot and
// projects it onto the toolchain-judging shape: the intervals its toolchain
// affected block states, and the retraction stamp that decides whether a match
// against them still stands.
func readSnapshotAdvisory(files map[string]*zip.File, id string) (domain.ToolchainAdvisory, error) {
	f, ok := files["ID/"+id+".json"]
	if !ok {
		return domain.ToolchainAdvisory{}, fmt.Errorf("no ID/%s.json in the snapshot", id)
	}
	data, err := readZipFile(f, maxAdvisoryBytes)
	if err != nil {
		return domain.ToolchainAdvisory{}, err
	}
	var raw osvAdvisory
	if err := json.Unmarshal(data, &raw); err != nil {
		return domain.ToolchainAdvisory{}, fmt.Errorf("unmarshal advisory %s: %w", id, err)
	}

	adv := domain.ToolchainAdvisory{ID: id, Summary: raw.Summary}
	if raw.Withdrawn != nil {
		adv.WithdrawnAt = *raw.Withdrawn
	}
	for _, a := range raw.Affected {
		if a.Package.Name != domain.ToolchainModulePath {
			continue
		}
		for _, r := range a.Ranges {
			// Only SEMVER ranges are version-comparable. A range in another
			// vocabulary states nothing this judgment can read, and inventing a
			// bound for it would manufacture coverage.
			if r.Type != "" && r.Type != "SEMVER" {
				continue
			}
			adv.Ranges = append(adv.Ranges, toolchainRanges(r.Events)...)
		}
	}
	return adv, nil
}

// toolchainRanges flattens OSV's event list — a sequence of introduced and fixed
// boundaries — into the explicit intervals the domain judges against. A trailing
// introduced with no fixed after it is an interval with no upper bound.
func toolchainRanges(events []osvEvent) []domain.ToolchainRange {
	var out []domain.ToolchainRange
	open := false
	current := domain.ToolchainRange{}
	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			if open {
				out = append(out, current)
			}
			current = domain.ToolchainRange{Introduced: ev.Introduced}
			open = true
		case ev.Fixed != "":
			current.Fixed = ev.Fixed
			out = append(out, current)
			current = domain.ToolchainRange{}
			open = false
		}
	}
	if open {
		out = append(out, current)
	}
	return out
}

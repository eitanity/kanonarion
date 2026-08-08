package domain

import "testing"

// An entry that carries an identifier is classified whatever the input claimed:
// the measurement is derived from what is there, so it can never contradict it.
func TestMeasurement_DerivedFromTheIdentifier(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input CompatibilityInput
		want  LicenceMeasurement
	}{
		{
			name:  "identifier present",
			input: CompatibilityInput{SPDX: "MIT"},
			want:  MeasurementClassified,
		},
		{
			name:  "identifier present, input claims otherwise",
			input: CompatibilityInput{SPDX: "MIT", Measurement: MeasurementUnmeasured},
			want:  MeasurementClassified,
		},
		{
			name:  "dual licence carries its arms",
			input: CompatibilityInput{ElectiveArms: []string{"MIT", "GPL-3.0-only"}},
			want:  MeasurementClassified,
		},
		{
			// The zero value: an input built before this axis existed, or by a
			// caller that never set it, means what an empty identifier has
			// always meant — nothing has been measured.
			name:  "no identifier, nothing declared",
			input: CompatibilityInput{},
			want:  MeasurementUnmeasured,
		},
		{
			name:  "no identifier, record exists",
			input: CompatibilityInput{Measurement: MeasurementUnclassifiable},
			want:  MeasurementUnclassifiable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := measurementOf(tc.input); got != tc.want {
				t.Errorf("measurementOf = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLicenceMeasurement_WireNames(t *testing.T) {
	t.Parallel()
	for m, want := range map[LicenceMeasurement]string{
		MeasurementUnmeasured:     "unmeasured",
		MeasurementUnclassifiable: "unclassifiable",
		MeasurementClassified:     "classified",
		LicenceMeasurement(99):    "unmeasured",
	} {
		if got := m.String(); got != want {
			t.Errorf("LicenceMeasurement(%d).String() = %q, want %q", m, got, want)
		}
	}
}

// The measurement must survive the engine onto every entry it can appear on: a
// plain unknown pair and a dual licence whose election is still open.
func TestCheckClosureCompatibility_CarriesMeasurementOntoConflicts(t *testing.T) {
	t.Parallel()
	report := CheckClosureCompatibility([]CompatibilityInput{
		{ModulePath: "example.com/absent", ModuleVersion: "v1.0.0"},
		{ModulePath: "example.com/unclassifiable", ModuleVersion: "v1.0.0", Measurement: MeasurementUnclassifiable},
		{ModulePath: "example.com/dual", ModuleVersion: "v1.0.0", ElectiveArms: []string{"MIT", "GPL-3.0-only"}},
	}, "MIT")

	want := map[string]LicenceMeasurement{
		"example.com/absent":         MeasurementUnmeasured,
		"example.com/unclassifiable": MeasurementUnclassifiable,
		"example.com/dual":           MeasurementClassified,
	}
	got := map[string]LicenceMeasurement{}
	for _, c := range report.Conflicts {
		got[c.ModulePath] = c.Measurement
	}
	for module, w := range want {
		if got[module] != w {
			t.Errorf("%s measurement = %v, want %v", module, got[module], w)
		}
	}
}

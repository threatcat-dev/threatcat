package modelmerger

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

type dummyChangelog struct{}

func (dc dummyChangelog) AddEntry(string) {}

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		assets   mergeableAssets
		expected string
	}{
		{
			name: "ThreatDragon has priority",
			assets: newMergeableAssets(
				[]common.Asset{
					{DisplayName: "DockerName", Source: common.DataSourceDockerCompose},
					{DisplayName: "ThreatName", Source: common.DataSourceThreatDragon}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),

			expected: "ThreatName",
		},
		{
			name: "DockerCompose takes fallback when no ThreatDragon",
			assets: newMergeableAssets(
				[]common.Asset{
					{DisplayName: "DockerName", Source: common.DataSourceDockerCompose},
					{DisplayName: "UnknownName", Source: common.DataSourceUnknown}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: "DockerName",
		},
		{
			name: "Unknown used when no higher priority",
			assets: newMergeableAssets(
				[]common.Asset{
					{DisplayName: "UnknownName", Source: common.DataSourceUnknown}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: "UnknownName",
		},
		{
			name: "Already merged asset just returns the display name",
			assets: newMergeableAssets(
				[]common.Asset{
					{DisplayName: "Merged", Source: common.DataSourceMerged}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: "Merged",
		},
		{
			name:     "Empty input returns empty string",
			assets:   newMergeableAssets([]common.Asset{}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assets.displayName(tt.assets.as, slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAssetType(t *testing.T) {
	tests := []struct {
		name     string
		assets   mergeableAssets
		expected common.AssetType
	}{
		{
			name: "DockerCompose has highest priority",
			assets: newMergeableAssets(
				[]common.Asset{
					{Type: common.AssetTypeWebserver, Source: common.DataSourceDockerCompose},
					{Type: common.AssetTypeDatabase, Source: common.DataSourceThreatDragon}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: common.AssetTypeWebserver,
		},
		{
			name: "ThreatDragon used if no DockerCompose",
			assets: newMergeableAssets(
				[]common.Asset{
					{Type: common.AssetTypeApplication, Source: common.DataSourceThreatDragon},
					{Type: common.AssetTypeWebserver, Source: common.DataSourceUnknown}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: common.AssetTypeApplication,
		},
		{
			name: "Unknown used if no preferred source",
			assets: newMergeableAssets(
				[]common.Asset{
					{Type: common.AssetTypeDatabase, Source: common.DataSourceUnknown}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: common.AssetTypeDatabase,
		},
		{
			name: "No matching source results in AssetTypeUnknown",
			assets: newMergeableAssets(
				[]common.Asset{
					{Type: common.AssetTypeApplication, Source: common.DataSourceMerged}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: common.AssetTypeUnknown,
		},
		{
			name:     "Empty input returns AssetTypeUnknown",
			assets:   newMergeableAssets([]common.Asset{}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto),
			expected: common.AssetTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assets.assetType(tt.assets.as, slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtraMerge(t *testing.T) {
	tests := []struct {
		name     string
		assets   mergeableAssets
		expected map[string]any
	}{
		{
			name: "Merges keys from multiple assets",
			assets: newMergeableAssets(
				[]common.Asset{
					{Extra: map[string]any{"a": 1, "b": 2}},
					{Extra: map[string]any{"c": 3}}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: map[string]any{"a": 1, "b": 2, "c": 3},
		},
		{
			name: "Later keys overwrite earlier keys",
			assets: newMergeableAssets(
				[]common.Asset{
					{Extra: map[string]any{"key": "first"}},
					{Extra: map[string]any{"key": "second"}}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: map[string]any{"key": "second"},
		},
		{
			name: "Handles empty extra maps gracefully",
			assets: newMergeableAssets(
				[]common.Asset{
					{Extra: map[string]any{}},
					{Extra: map[string]any{"x": true}}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: map[string]any{"x": true},
		},
		{
			name:     "Empty input returns empty map",
			assets:   newMergeableAssets([]common.Asset{}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto),
			expected: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assets.extra(slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name      string
		assets    mergeableAssets
		expected  common.Asset
		wantPanic bool
	}{
		{
			name: "Single asset returns unchanged",
			assets: newMergeableAssets(
				[]common.Asset{
					{
						ID:          "a1",
						DisplayName: "App",
						Type:        common.AssetTypeApplication,
						Source:      common.DataSourceThreatDragon,
						Extra:       map[string]any{"foo": "bar"},
					}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),

			expected: common.Asset{
				ID:          "a1",
				DisplayName: "App",
				Type:        common.AssetTypeApplication,
				Source:      common.DataSourceThreatDragon,
				Extra:       map[string]any{"foo": "bar"},
			},
		},
		{
			name: "Merges multiple assets with same ID",
			assets: newMergeableAssets(
				[]common.Asset{
					{
						ID:          "db1",
						DisplayName: "DB from ThreatDragon",
						Type:        common.AssetTypeDatabase,
						Source:      common.DataSourceThreatDragon,
						Extra:       map[string]any{"env": "prod"},
					},
					{
						ID:          "db1",
						DisplayName: "DB from Docker",
						Type:        common.AssetTypeWebserver, // will be overridden
						Source:      common.DataSourceDockerCompose,
						Extra:       map[string]any{"version": "1.2"},
					}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: common.Asset{
				ID:          "db1",
				DisplayName: "DB from ThreatDragon",
				Type:        common.AssetTypeWebserver,
				Source:      common.DataSourceMerged,
				Extra: map[string]any{
					"env":     "prod",
					"version": "1.2",
				},
			},
		},
		{
			name:      "Panics on empty asset slice",
			assets:    newMergeableAssets([]common.Asset{}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto),
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				assert.Panics(t, func() {
					_ = tt.assets.merge(slog.Default(), dummyChangelog{})
				})
			} else {
				result := tt.assets.merge(slog.Default(), dummyChangelog{})
				assert.Equal(t, tt.expected.ID, result.ID)
				assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
				assert.Equal(t, tt.expected.Type, result.Type)
				assert.Equal(t, tt.expected.Source, result.Source)
				assert.Equal(t, tt.expected.Extra, result.Extra)
			}
		})
	}
}

func TestMergeableAssets_ThreatsPriority(t *testing.T) {

	tdThreats := []common.Threat{{ID: "threat1", Title: "TD", Type: common.DenialOfService}}
	dcThreats := []common.Threat{{ID: "threat1", Title: "DC", Type: common.DenialOfService}}
	unkThreats := []common.Threat{{ID: "threat1", Title: "UNK", Type: common.ThreatTypeUnknown}}

	tdAsset := common.Asset{ID: "a", Source: common.DataSourceThreatDragon, Threats: tdThreats}
	dcAsset := common.Asset{ID: "a", Source: common.DataSourceDockerCompose, Threats: dcThreats}
	unkAsset := common.Asset{ID: "a", Source: common.DataSourceUnknown, Threats: unkThreats}

	tests := []struct {
		name     string
		assets   mergeableAssets
		expected []common.Threat
	}{
		{
			name: "prefer ThreatDragon",
			assets: newMergeableAssets(
				[]common.Asset{tdAsset, dcAsset, unkAsset},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: tdThreats,
		},
		{
			name: "prefer DockerCompose when no ThreatDragon",
			assets: newMergeableAssets(
				[]common.Asset{dcAsset, unkAsset},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: dcThreats,
		},
		{
			name: "fallback to Unknown",
			assets: newMergeableAssets(
				[]common.Asset{unkAsset},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: nil,
		},
		{
			name: "empty slices produce nil/empty result",
			assets: newMergeableAssets(
				[]common.Asset{{ID: "x", Source: common.DataSourceUnknown, Threats: nil}},
				assetDisplayNameAuto,
				assetTypeAuto,
				prioritizeThreatsAuto),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.assets.threats(slog.Default(), dummyChangelog{})

			// assert length first, bail out on mismatch to avoid index errors
			if !assert.Equal(t, len(tt.expected), len(got), "unexpected length: got %d want %d", len(got), len(tt.expected)) {
				return
			}

			for i := range got {
				assert.Equal(t, tt.expected[i].ID, got[i].ID, "mismatch ID at idx %d", i)
				assert.Equal(t, tt.expected[i].Title, got[i].Title, "mismatch Title at idx %d", i)
			}
		})
	}
}

func TestPrioritizeThreatsManual(t *testing.T) {
	// 1. Save and Restore global function pointers
	oldConfirmation := getUserInputAsText
	oldInput := getUserInputAsUnsignedInt
	defer func() {
		getUserInputAsText = oldConfirmation
		getUserInputAsUnsignedInt = oldInput
	}()

	tests := []struct {
		name           string
		threats        []common.Threat
		mockConfirm    string
		mockIndex      uint
		wantFirstTitle string
	}{
		{
			name: "All threats equivalent - uses auto-prioritization",
			threats: []common.Threat{
				{ID: "T1", Title: "Same", Source: common.DataSourceDockerCompose},
				{ID: "T1", Title: "Same", Source: common.DataSourceThreatDragon},
			},
			// allThreatsEquivalent returns true, loop and confirmation are skipped
			wantFirstTitle: "Same",
		},
		{
			name: "Different threats - user confirms auto result",
			threats: []common.Threat{
				{ID: "T1", Title: "Threat A"},
				{ID: "T2", Title: "Threat B"},
			},
			mockConfirm:    "y",
			wantFirstTitle: "Threat A", // Assuming Auto returns first item
		},
		{
			name: "Different threats - user selects index 1 manually",
			threats: []common.Threat{
				{ID: "T1", Title: "Threat A"},
				{ID: "T2", Title: "Threat B"},
			},
			mockConfirm:    "n",
			mockIndex:      1,
			wantFirstTitle: "Threat B", // Selection swaps index 1 to index 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 2. Set the mocks for this specific test case
			getUserInputAsText = func() (string, error) {
				return tt.mockConfirm, nil
			}
			getUserInputAsUnsignedInt = func() (uint, error) {
				return tt.mockIndex, nil
			}

			got := pioritizeThreatsManual(tt.threats)

			// 3. Verify the outcome
			if got[0].Title != tt.wantFirstTitle {
				t.Errorf("PrioritizeThreatsManual() first threat = %v, want title %v",
					got[0].Title, tt.wantFirstTitle)
			}
		})
	}
}

// TestGenerate_ExcludeThreatsWithUnknownTypeOrModel tests that unkown threat types or not supported models should be excluded
func TestGenerate_ExcludeThreatsWithUnknownTypeOrModel(t *testing.T) {
	tdThreats := []common.Threat{
		{ID: "threat1", Title: "Valid Threat", Type: common.Spoofing, ModelType: common.STRIDE},
		{ID: "threat2", Title: "Unknown Type Threat", Type: common.ThreatTypeUnknown, ModelType: common.STRIDE},
		{ID: "threat3", Title: "Unknown Model Threat", Type: common.Spoofing, ModelType: common.NotSupported},
	}
	tdAsset := []common.Asset{{ID: "a", Source: common.DataSourceThreatDragon, Threats: tdThreats}}

	mergeableAssets := newMergeableAssets(tdAsset, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto)

	mergedThreats := mergeableAssets.threats(slog.Default(), dummyChangelog{})
	assert.Equal(t, 1, len(mergedThreats), "Expected 1 threat in merged asset, got %d", len(mergedThreats))
	assert.Equal(t, "threat1", mergedThreats[0].ID, "Expected threat ID 'threat1', got '%s'", mergedThreats[0].ID)
}

// TestGenerate_MitigateOriginalMissingThreats tests that threats present in the original ThreatDragon model but missing in the DockerCompose model are marked as Mitigated
func TestGenerate_MitigateOriginalMissingThreats(t *testing.T) {
	tdThreats := []common.Threat{
		{ID: "threat1", Title: "Present Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceThreatDragon, Status: common.Open},
		{ID: "threat2", Title: "Not Present Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceThreatDragon, Status: common.Open},
	}
	dcThreats := []common.Threat{
		{ID: "threat1", Title: "Present Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceDockerCompose, Status: common.Open},
	}

	tdAsset := common.Asset{ID: "a", Source: common.DataSourceThreatDragon, Threats: tdThreats}
	dcAsset := common.Asset{ID: "a", Source: common.DataSourceDockerCompose, Threats: dcThreats}

	mergeableAssets := newMergeableAssets([]common.Asset{tdAsset, dcAsset}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto)

	mergedThreats := mergeableAssets.threats(slog.Default(), dummyChangelog{})
	assert.Equal(t, 2, len(mergedThreats), "Expected 2 threats in merged asset, got %d", len(mergedThreats))
	for _, threat := range mergedThreats {
		switch threat.ID {
		case "threat1":
			assert.Equal(t, common.Open, threat.Status, "Expected threat1 to be Open, got %s", threat.Status.String())
		case "threat2":
			assert.Equal(t, common.Mitigated, threat.Status, "Expected threat2 to be Mitigated, got %s", threat.Status.String())
		}
	}
}

// TestGenerate_PreserveUserGeneratedThreats tests that user-generated threats are preserved during the merge process
func TestGenerate_PreserveUserGeneratedThreats(t *testing.T) {
	tdThreats := []common.Threat{
		{ID: "threat1", Title: "User Generated Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: true, Source: common.DataSourceThreatDragon, Status: common.Open},
	}
	tdAsset := common.Asset{ID: "a", Source: common.DataSourceThreatDragon, Threats: tdThreats}
	mergeableAssets := newMergeableAssets([]common.Asset{tdAsset}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto)

	mergedThreats := mergeableAssets.threats(slog.Default(), dummyChangelog{})
	assert.Equal(t, 1, len(mergedThreats), "Expected 1 threat in merged asset, got %d", len(mergedThreats))
	assert.Equal(t, "threat1", mergedThreats[0].ID, "Expected threat ID 'threat1', got '%s'", mergedThreats[0].ID)
	assert.True(t, mergedThreats[0].IsGeneratedByUser, "Expected threat to be user-generated")
}

// TestGenerate_PreserveThreatStatus tests that the status of threats is preserved during the merge process if they are present in both assets
func TestGenerate_DoNotMitigateOriginalNotMissingThreats(t *testing.T) {
	tdThreats := []common.Threat{
		{ID: "threat1", Title: "Present Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceThreatDragon, Status: common.Open},
		{ID: "threat2", Title: "User Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceThreatDragon, Status: common.Open},
		{ID: "threat3", Title: "User Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: true, Source: common.DataSourceThreatDragon, Status: common.Open},
	}
	dcThreats := []common.Threat{
		{ID: "threat1", Title: "Present Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceDockerCompose, Status: common.Open},
		{ID: "threat2", Title: "User Threat", Type: common.Spoofing, ModelType: common.STRIDE, IsGeneratedByUser: false, Source: common.DataSourceDockerCompose, Status: common.Open},
	}

	tdAsset := common.Asset{ID: "a", Source: common.DataSourceThreatDragon, Threats: tdThreats}
	dcAsset := common.Asset{ID: "a", Source: common.DataSourceDockerCompose, Threats: dcThreats}

	mergeableAssets := newMergeableAssets([]common.Asset{tdAsset, dcAsset}, assetDisplayNameAuto, assetTypeAuto, prioritizeThreatsAuto)

	mergedThreats := mergeableAssets.threats(slog.Default(), dummyChangelog{})
	assert.Equal(t, 3, len(mergedThreats), "Expected 2 threats in merged asset, got %d", len(mergedThreats))
	for _, threat := range mergedThreats {
		switch threat.ID {
		case "threat1":
			assert.Equal(t, common.Open, threat.Status, "Expected threat1 to be Open, got %s", threat.Status.String())
		case "threat2":
			assert.Equal(t, common.Open, threat.Status, "Expected threat2 to be Open, got %s", threat.Status.String())
		case "threat3":
			assert.Equal(t, common.Open, threat.Status, "Expected threat3 to be Open, got %s", threat.Status.String())
		}
	}
}

func TestAllThreatsEquivalent(t *testing.T) {
	tests := []struct {
		name     string
		threats  []common.Threat
		expected bool
	}{
		{
			name:     "Empty slice returns true",
			threats:  []common.Threat{},
			expected: true,
		},
		{
			name: "Single threat returns true",
			threats: []common.Threat{
				{ID: "t1", Title: "Threat 1", Source: common.DataSourceThreatDragon},
			},
			expected: true,
		},
		{
			name: "Identical threats with different sources are equivalent",
			threats: []common.Threat{
				{ID: "t1", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
				{ID: "t1", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceDockerCompose},
			},
			expected: true,
		},
		{
			name: "Different threat titles are not equivalent",
			threats: []common.Threat{
				{ID: "t1", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
				{ID: "t1", Title: "Threat 2", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
			},
			expected: false,
		},
		{
			name: "Different threat types are not equivalent",
			threats: []common.Threat{
				{ID: "t1", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
				{ID: "t1", Title: "Threat 1", Type: common.Tampering, Source: common.DataSourceThreatDragon},
			},
			expected: false,
		},
		{
			name: "Different threat IDs are not equivalent",
			threats: []common.Threat{
				{ID: "t1", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
				{ID: "t2", Title: "Threat 1", Type: common.Spoofing, Source: common.DataSourceThreatDragon},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := allThreatsEquivalent(tt.threats)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// can you provide test for the dataflow merge logic
// TestDataFlowDisplayName tests the DataFlowDisplayNameAuto strategy
func TestDataFlowDisplayName(t *testing.T) {
	tests := []struct {
		name     string
		flows    []common.DataFlow
		expected string
	}{
		{
			name: "ThreatDragon has priority",
			flows: []common.DataFlow{
				{Source: "a", Target: "b", Name: "From ThreatDragon", DataSource: common.DataSourceThreatDragon},
				{Source: "a", Target: "b", Name: "From DockerCompose", DataSource: common.DataSourceDockerCompose},
			},
			expected: "From ThreatDragon",
		},
		{
			name: "DockerCompose used if no ThreatDragon",
			flows: []common.DataFlow{
				{Source: "a", Target: "b", Name: "From DockerCompose", DataSource: common.DataSourceDockerCompose},
				{Source: "a", Target: "b", Name: "From Unknown", DataSource: common.DataSourceUnknown},
			},
			expected: "From DockerCompose",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dataFlowDisplayNameAuto(tt.flows, slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDataFlowExtra tests the extra merge logic for dataflows
func TestDataFlowExtra(t *testing.T) {
	tests := []struct {
		name     string
		flows    []common.DataFlow
		expected map[string]any
	}{
		{
			name: "Merges keys from multiple dataflows",
			flows: []common.DataFlow{
				{Source: "a", Target: "b", Extra: map[string]any{"a": 1, "b": 2}},
				{Source: "a", Target: "b", Extra: map[string]any{"c": 3}},
			},
			expected: map[string]any{"a": 1, "b": 2, "c": 3},
		},
		{
			name: "Later keys overwrite earlier keys",
			flows: []common.DataFlow{
				{Source: "a", Target: "b", Extra: map[string]any{"key": "first"}},
				{Source: "a", Target: "b", Extra: map[string]any{"key": "second"}},
			},
			expected: map[string]any{"key": "second"},
		},
		{
			name: "Handles empty extra maps gracefully",
			flows: []common.DataFlow{
				{Source: "a", Target: "b", Extra: map[string]any{}},
				{Source: "a", Target: "b", Extra: map[string]any{"x": true}},
			},
			expected: map[string]any{"x": true},
		},
		{
			name:     "Empty input returns empty map",
			flows:    []common.DataFlow{},
			expected: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdf := mergeableDataFlows{dfs: tt.flows}
			result := mdf.extra(slog.Default())
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDataFlowTechnicalPropertiesAuto tests the DataFlowTechnicalPropertiesAuto strategy
func TestDataFlowTechnicalPropertiesAuto(t *testing.T) {
	tests := []struct {
		name     string
		flows    []common.DataFlow
		expected common.DataFlow
	}{
		{
			name: "DockerCompose has priority over ThreatDragon",
			flows: []common.DataFlow{
				{
					Source:        "td-src",
					Target:        "td-tgt",
					Protocol:      "HTTP",
					Encrypted:     false,
					PublicNetwork: true,
					Bidirectional: true,
					DataSource:    common.DataSourceThreatDragon,
				},
				{
					Source:        "dc-src",
					Target:        "dc-tgt",
					Protocol:      "HTTPS",
					Encrypted:     true,
					PublicNetwork: false,
					Bidirectional: false,
					DataSource:    common.DataSourceDockerCompose,
				},
			},
			expected: common.DataFlow{
				Source:        "dc-src",
				Target:        "dc-tgt",
				Protocol:      "HTTPS",
				Encrypted:     true,
				PublicNetwork: false,
				Bidirectional: false,
				DataSource:    common.DataSourceDockerCompose,
			},
		},
		{
			name: "ThreatDragon used if no DockerCompose",
			flows: []common.DataFlow{
				{
					Source:        "td-src",
					Target:        "td-tgt",
					Protocol:      "TCP",
					Encrypted:     true,
					PublicNetwork: false,
					Bidirectional: true,
					DataSource:    common.DataSourceThreatDragon,
				},
				{
					Source:        "unknown-src",
					Target:        "unknown-tgt",
					Protocol:      "UDP",
					Encrypted:     false,
					PublicNetwork: true,
					Bidirectional: false,
					DataSource:    common.DataSourceUnknown,
				},
			},
			expected: common.DataFlow{
				Source:        "td-src",
				Target:        "td-tgt",
				Protocol:      "TCP",
				Encrypted:     true,
				PublicNetwork: false,
				Bidirectional: true,
				DataSource:    common.DataSourceThreatDragon,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dataFlowTechnicalPropertiesAuto(tt.flows, slog.Default())
			assert.Equal(t, tt.expected.Protocol, result.Protocol)
			assert.Equal(t, tt.expected.Encrypted, result.Encrypted)
			assert.Equal(t, tt.expected.PublicNetwork, result.PublicNetwork)
			assert.Equal(t, tt.expected.Source, result.Source)
			assert.Equal(t, tt.expected.Target, result.Target)
			assert.Equal(t, tt.expected.Bidirectional, result.Bidirectional)
		})
	}
}

// TestDataFlowMerge tests the merge method of mergeableDataFlows
func TestDataFlowMerge(t *testing.T) {
	tests := []struct {
		name      string
		flows     []common.DataFlow
		expected  common.DataFlow
		wantPanic bool
	}{
		{
			name: "Single dataflow returns unchanged",
			flows: []common.DataFlow{
				{
					ID:                "df1",
					Name:              "API Flow",
					Protocol:          "HTTPS",
					Encrypted:         true,
					PublicNetwork:     false,
					Source:            "service-a",
					Target:            "service-b",
					Bidirectional:     false,
					DataSource:        common.DataSourceThreatDragon,
					IsGeneratedByUser: false,
					Extra:             map[string]any{"foo": "bar"},
				},
			},
			expected: common.DataFlow{
				ID:                "df1",
				Name:              "API Flow",
				Protocol:          "HTTPS",
				Encrypted:         true,
				PublicNetwork:     false,
				Source:            "service-a",
				Target:            "service-b",
				Bidirectional:     false,
				DataSource:        common.DataSourceThreatDragon,
				IsGeneratedByUser: false,
				Extra:             map[string]any{"foo": "bar"},
			},
		},
		{
			name: "Merges multiple dataflows with same ID",
			flows: []common.DataFlow{
				{
					ID:                "df1",
					Name:              "From ThreatDragon",
					Protocol:          "HTTP",
					Encrypted:         false,
					PublicNetwork:     true,
					Source:            "src-td",
					Target:            "tgt-td",
					Bidirectional:     true,
					DataSource:        common.DataSourceThreatDragon,
					IsGeneratedByUser: false,
					Extra:             map[string]any{"env": "prod"},
				},
				{
					ID:                "df1",
					Name:              "From DockerCompose",
					Protocol:          "HTTPS",
					Encrypted:         true,
					PublicNetwork:     false,
					Source:            "src-dc",
					Target:            "tgt-dc",
					Bidirectional:     false,
					DataSource:        common.DataSourceDockerCompose,
					IsGeneratedByUser: false,
					Extra:             map[string]any{"version": "1.0"},
				},
			},
			expected: common.DataFlow{
				ID:                "df1",
				Name:              "From ThreatDragon",
				Protocol:          "HTTPS",
				Encrypted:         true,
				PublicNetwork:     false,
				Source:            "src-dc",
				Target:            "tgt-dc",
				Bidirectional:     false,
				DataSource:        common.DataSourceMerged,
				IsGeneratedByUser: false,
				Extra: map[string]any{
					"env":     "prod",
					"version": "1.0",
				},
			},
		},
		{
			name:      "Panics on empty dataflow slice",
			flows:     []common.DataFlow{},
			wantPanic: true,
		},
		{
			name: "Merges multiple dataflows with same ID and generated by user",
			flows: []common.DataFlow{
				{
					ID:                "df1",
					Name:              "From ThreatDragon",
					Protocol:          "HTTP",
					Encrypted:         false,
					PublicNetwork:     true,
					Source:            "src-td",
					Target:            "tgt-td",
					Bidirectional:     true,
					DataSource:        common.DataSourceThreatDragon,
					IsGeneratedByUser: true,
					Extra:             map[string]any{"env": "prod"},
				},
				{
					ID:                "df1",
					Name:              "From DockerCompose",
					Protocol:          "HTTPS",
					Encrypted:         true,
					PublicNetwork:     false,
					Source:            "src-dc",
					Target:            "tgt-dc",
					Bidirectional:     false,
					DataSource:        common.DataSourceDockerCompose,
					IsGeneratedByUser: false,
					Extra:             map[string]any{"version": "1.0"},
				},
			},
			expected: common.DataFlow{
				ID:                "df1",
				Name:              "From ThreatDragon",
				Protocol:          "HTTPS",
				Encrypted:         true,
				PublicNetwork:     false,
				Source:            "src-dc",
				Target:            "tgt-dc",
				Bidirectional:     false,
				DataSource:        common.DataSourceMerged,
				IsGeneratedByUser: true,
				Extra: map[string]any{
					"env":     "prod",
					"version": "1.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mdf := newMergeableDataFlows(
				tt.flows,
				dataFlowDisplayNameAuto,
				dataFlowTechnicalPropertiesAuto,
				prioritizeThreatsAuto,
			)
			if tt.wantPanic {
				assert.Panics(t, func() {
					_ = mdf.merge(slog.Default(), dummyChangelog{})
				})
			} else {
				result := mdf.merge(slog.Default(), dummyChangelog{})
				assert.Equal(t, tt.expected.ID, result.ID)
				assert.Equal(t, tt.expected.Name, result.Name)
				assert.Equal(t, tt.expected.Protocol, result.Protocol)
				assert.Equal(t, tt.expected.Encrypted, result.Encrypted)
				assert.Equal(t, tt.expected.PublicNetwork, result.PublicNetwork)
				assert.Equal(t, tt.expected.Source, result.Source)
				assert.Equal(t, tt.expected.Target, result.Target)
				assert.Equal(t, tt.expected.Bidirectional, result.Bidirectional)
				assert.Equal(t, tt.expected.DataSource, result.DataSource)
				assert.Equal(t, tt.expected.Extra, result.Extra)
				assert.Equal(t, tt.expected.IsGeneratedByUser, result.IsGeneratedByUser)
			}
		})
	}
}

func TestDataFlowTechnicalPropertiesManual(t *testing.T) {

	oldConfirmation := getUserInputAsText
	oldInput := getUserInputAsUnsignedInt
	defer func() {
		getUserInputAsText = oldConfirmation
		getUserInputAsUnsignedInt = oldInput
	}()

	logger := slog.Default()

	tests := []struct {
		name         string
		dfs          []common.DataFlow
		mockConfirm  string
		mockIndex    uint
		mockErr      error
		wantProtocol string
	}{
		{
			name: "All properties identical - returns auto result immediately",
			dfs: []common.DataFlow{
				{ID: "df1", Protocol: "HTTPS", DataSource: common.DataSourceDockerCompose},
				{ID: "df1", Protocol: "HTTPS", DataSource: common.DataSourceThreatDragon},
			},
			wantProtocol: "HTTPS",
		},
		{
			name: "Different properties - user confirms auto result",
			dfs: []common.DataFlow{
				{ID: "df1", Protocol: "HTTPS"},
				{ID: "df1", Protocol: "HTTP"},
			},
			mockConfirm:  "y",
			wantProtocol: "HTTPS", // Assuming Auto picks index 0
		},
		{
			name: "Different properties - user selects second option manually",
			dfs: []common.DataFlow{
				{ID: "df1", Protocol: "HTTPS"},
				{ID: "df1", Protocol: "SSH"},
			},
			mockConfirm:  "n",
			mockIndex:    1,
			wantProtocol: "SSH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 2. Set up the mocks for this specific test case
			getUserInputAsText = func() (string, error) {
				return tt.mockConfirm, nil
			}
			getUserInputAsUnsignedInt = func() (uint, error) {
				return tt.mockIndex, tt.mockErr
			}

			got := dataFlowTechnicalPropertiesManual(tt.dfs, logger)

			if got.Protocol != tt.wantProtocol {
				t.Errorf("Expected protocol %s, got %s", tt.wantProtocol, got.Protocol)
			}
		})
	}
}
func TestTrustBoundaryDisplayNameMergeAuto(t *testing.T) {
	tests := []struct {
		name       string
		boundaries []common.TrustBoundary
		expected   common.TrustBoundary
	}{
		{
			name: "TrustBoundary from threat dragon source should be prioritized over docker-compose",
			boundaries: []common.TrustBoundary{
				{
					ID:          "id1",
					DisplayName: "Boundary Name Threat",
					Source:      common.DataSourceThreatDragon,
				},
				{
					ID:          "id1",
					DisplayName: "Boundary Name Docker",
					Source:      common.DataSourceDockerCompose,
				},
			},
			expected: common.TrustBoundary{
				ID:          "id1",
				DisplayName: "Boundary Name Threat",
				Source:      common.DataSourceThreatDragon,
			},
		},
		{
			name: "TrustBoundary from docker-compose source should be prioritized over unknown",
			boundaries: []common.TrustBoundary{
				{
					ID:          "id1",
					DisplayName: "Boundary Name Unknown",
					Source:      common.DataSourceUnknown,
				},
				{
					ID:          "id1",
					DisplayName: "Boundary Name Docker",
					Source:      common.DataSourceDockerCompose,
				},
			},
			expected: common.TrustBoundary{
				ID:          "id1",
				DisplayName: "Boundary Name Docker",
				Source:      common.DataSourceDockerCompose,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			displayName := boundaryDisplayNameAuto(tt.boundaries, slog.Default())
			assert.Equal(t, displayName, tt.expected.DisplayName)
		})
	}
}

func TestTrustBoundaryDisplayNameMergeManual(t *testing.T) {
	tests := []struct {
		name       string
		boundaries []common.TrustBoundary
		expected   common.TrustBoundary
	}{
		{
			name: "TrustBoundary from threat dragon source should be prioritized over docker-compose",
			boundaries: []common.TrustBoundary{
				{
					ID:          "id1",
					DisplayName: "Boundary Name Docker",
					Source:      common.DataSourceDockerCompose,
				},
				{
					ID:          "id1",
					DisplayName: "Boundary Name Threat",
					Source:      common.DataSourceThreatDragon,
				},
			},
			expected: common.TrustBoundary{
				ID:          "id1",
				DisplayName: "Boundary Name Docker",
				Source:      common.DataSourceDockerCompose,
			},
		},
		{
			name: "TrustBoundary from docker-compose source should be prioritized over unknown",
			boundaries: []common.TrustBoundary{
				{
					ID:          "id1",
					DisplayName: "Boundary Name Unknown",
					Source:      common.DataSourceUnknown,
				},
				{
					ID:          "id1",
					DisplayName: "Boundary Name Docker",
					Source:      common.DataSourceDockerCompose,
				},
			},
			expected: common.TrustBoundary{
				ID:          "id1",
				DisplayName: "Boundary Name Unknown",
				Source:      common.DataSourceUnknown,
			},
		},
	}

	// Save the real functions so we can restore them after the test
	originalFuncStr := getUserInputAsText
	defer func() { getUserInputAsText = originalFuncStr }()

	originalFuncInt := getUserInputAsUnsignedInt
	defer func() { getUserInputAsUnsignedInt = originalFuncInt }()

	// Overwrite the global functions with our mocks
	getUserInputAsText = func() (string, error) {
		return "n", nil // dont accept automerge
	}

	getUserInputAsUnsignedInt = func() (uint, error) {
		return 0, nil //always select first option
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			displayName := boundaryDisplayNameManual(tt.boundaries, slog.Default())
			assert.Equal(t, displayName, tt.expected.DisplayName)
		})
	}
}

func TestModelMerger_AutoMerge(t *testing.T) {
	tests := []struct {
		name     string
		input    []common.ThreatModel
		expected common.ThreatModel
	}{
		{
			name:  "Returns empty model for empty input",
			input: []common.ThreatModel{},
			expected: common.ThreatModel{
				Assets: []common.Asset{},
				Extra:  map[string]any{},
			},
		},
		{
			name: "Returns single model as-is",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
					},
					Extra: map[string]any{"source": "single"},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
				},
				Extra: map[string]any{"source": "single"},
			},
		},
		{
			name: "Merges big ThreatModel with same ID",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{
							ID:          "shared",
							DisplayName: "From ThreatDragon",
							Type:        common.AssetTypeDatabase,
							Source:      common.DataSourceThreatDragon,
							Extra:       map[string]any{"owner": "teamA"},
						},
					},
					DataFlows: []common.DataFlow{
						{Source: "a", Target: "b", Name: "From ThreatDragon", DataSource: common.DataSourceThreatDragon},
					},
					Boundaries: []common.TrustBoundary{
						{
							ID:          "id1",
							DisplayName: "Boundary Name Docker",
							Source:      common.DataSourceDockerCompose,
						},
					}, // Added missing comma here
					Extra: map[string]any{"env": "staging"},
				},
				{
					Assets: []common.Asset{
						{
							ID:          "shared",
							DisplayName: "From Docker",
							Type:        common.AssetTypeWebserver,
							Source:      common.DataSourceDockerCompose,
							Extra:       map[string]any{"version": "1.0"},
						},
					},
					DataFlows: []common.DataFlow{
						{Source: "a", Target: "b", Name: "From DockerCompose", DataSource: common.DataSourceDockerCompose},
					},
					Boundaries: []common.TrustBoundary{
						{
							ID:          "id1",
							DisplayName: "Boundary Name Threat",
							Source:      common.DataSourceThreatDragon,
						},
					},
					Extra: map[string]any{"version": "latest"},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{
						ID:          "shared",
						DisplayName: "From ThreatDragon",       // priority: ThreatDragon
						Type:        common.AssetTypeWebserver, // priority: DockerCompose
						Source:      common.DataSourceMerged,
						Extra: map[string]any{
							"owner":   "teamA",
							"version": "1.0", // from DockerCompose asset
						},
					},
				},
				DataFlows: []common.DataFlow{
					{Source: "a", Target: "b", Name: "From ThreatDragon", DataSource: common.DataSourceMerged, Extra: map[string]any{}},
				},
				Boundaries: []common.TrustBoundary{
					{
						ID:          "id1",
						DisplayName: "Boundary Name Threat",
						Source:      common.DataSourceThreatDragon,
					},
				},
				Extra: map[string]any{
					"env":     "staging",
					"version": "latest", // overwritten by second model
				},
			},
		},
		{
			name: "Keeps distinct assets",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a1", DisplayName: "A1", Type: common.AssetTypeApplication},
					},
				},
				{
					Assets: []common.Asset{
						{ID: "a2", DisplayName: "A2", Type: common.AssetTypeWebserver},
					},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a1", DisplayName: "A1", Type: common.AssetTypeApplication},
					{ID: "a2", DisplayName: "A2", Type: common.AssetTypeWebserver},
				},
				Extra: map[string]any{},
			},
		},
		{
			name: "Returns single model with DataFlows as-is",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
					},
					Extra: map[string]any{"source": "single"},
					DataFlows: []common.DataFlow{
						{
							ID:                "dfa",
							Name:              "dfa",
							Encrypted:         true,
							PublicNetwork:     true,
							Source:            "a",
							Target:            "unknonw",
							Bidirectional:     false,
							DataSource:        common.DataSourceThreatDragon,
							IsGeneratedByUser: true,
						},
					},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
				},
				Extra: map[string]any{"source": "single"},
				DataFlows: []common.DataFlow{
					{
						ID:                "dfa",
						Name:              "dfa",
						Encrypted:         true,
						PublicNetwork:     true,
						Source:            "a",
						Target:            "unknonw",
						Bidirectional:     false,
						DataSource:        common.DataSourceThreatDragon,
						IsGeneratedByUser: true,
					},
				},
			},
		},
		{
			name: "Merge two identical models with DataFlows into one",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
					},
					Extra: map[string]any{"source": "single"},
					DataFlows: []common.DataFlow{
						{
							ID:                "dfa",
							Name:              "dfa",
							Encrypted:         true,
							PublicNetwork:     true,
							Source:            "a",
							Target:            "unknonw",
							Bidirectional:     false,
							DataSource:        common.DataSourceThreatDragon,
							IsGeneratedByUser: true,
						},
					},
				},
				{
					Assets: []common.Asset{
						{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
					},
					Extra: map[string]any{"source": "single"},
					DataFlows: []common.DataFlow{
						{
							ID:                "dfa",
							Name:              "dfa",
							Encrypted:         true,
							PublicNetwork:     true,
							Source:            "a",
							Target:            "unknonw",
							Bidirectional:     false,
							DataSource:        common.DataSourceThreatDragon,
							IsGeneratedByUser: true,
						},
					},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a", DisplayName: "A",
						Type:   common.AssetTypeApplication,
						Source: common.DataSourceMerged,
						Extra:  make(map[string]any, 0)},
				},
				Extra: map[string]any{"source": "single"},
				DataFlows: []common.DataFlow{
					{
						ID:                "dfa",
						Name:              "dfa",
						Encrypted:         true,
						PublicNetwork:     true,
						Source:            "a",
						Target:            "unknonw",
						Bidirectional:     false,
						DataSource:        common.DataSourceMerged,
						IsGeneratedByUser: true,
						Extra:             make(map[string]any, 0),
					},
				},
			},
		},
	}

	// Test Case 1:  full automatic merge
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merger := NewModelMerger(dummyChangelog{}, slog.Default(), false)
			result := merger.Merge(tt.input)

			// Compare assets (ignore order)
			assert.ElementsMatch(t, tt.expected.Assets, result.Assets)
			assert.ElementsMatch(t, tt.expected.DataFlows, result.DataFlows)

			// Compare extra fields
			assert.Equal(t, tt.expected.Extra, result.Extra)
		})
	}

	// Save the real functions so we can restore them after the test
	originalFunc := getUserInputAsText
	defer func() { getUserInputAsText = originalFunc }()

	// Overwrite the global functions with our mocks
	getUserInputAsText = func() (string, error) {
		return "y", nil // always accept automerge
	}

	// Test Case 2: Run model merger in manual mode but accept all automerge suggestions,
	// must behave identically to auto mode
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merger := NewModelMerger(dummyChangelog{}, slog.Default(), true)
			result := merger.Merge(tt.input)

			// Compare assets (ignore order)
			assert.ElementsMatch(t, tt.expected.Assets, result.Assets)
			assert.ElementsMatch(t, tt.expected.DataFlows, result.DataFlows)

			// Compare extra fields
			assert.Equal(t, tt.expected.Extra, result.Extra)
		})
	}
}

func TestModelMerger_ManualMerge(t *testing.T) {
	tests := []struct {
		name     string
		input    []common.ThreatModel
		expected common.ThreatModel
	}{
		{
			name:  "Returns empty model for empty input",
			input: []common.ThreatModel{},
			expected: common.ThreatModel{
				Assets: []common.Asset{},
				Extra:  map[string]any{},
			},
		},
		{
			name: "Returns single model as-is",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
					},
					Extra: map[string]any{"source": "single"},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a", DisplayName: "A", Type: common.AssetTypeApplication},
				},
				Extra: map[string]any{"source": "single"},
			},
		},
		{
			name: "Merges assets with same ID",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{
							ID:          "shared",
							DisplayName: "From ThreatDragon",
							Type:        common.AssetTypeDatabase,
							Source:      common.DataSourceThreatDragon,
							Extra:       map[string]any{"owner": "teamA"},
						},
					},
					Extra: map[string]any{"env": "staging"},
				},
				{
					Assets: []common.Asset{
						{
							ID:          "shared",
							DisplayName: "From Docker",
							Type:        common.AssetTypeWebserver,
							Source:      common.DataSourceDockerCompose,
							Extra:       map[string]any{"version": "1.0"},
						},
					},
					Extra: map[string]any{"version": "latest"},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{
						ID:          "shared",
						DisplayName: "From ThreatDragon",      // priority: ThreatDragon
						Type:        common.AssetTypeDatabase, // priority: DockerCompose
						Source:      common.DataSourceMerged,
						Extra: map[string]any{
							"owner":   "teamA",
							"version": "1.0", // from DockerCompose asset
						},
					},
				},
				Extra: map[string]any{
					"env":     "staging",
					"version": "latest", // overwritten by second model
				},
			},
		},
		{
			name: "Keeps distinct assets",
			input: []common.ThreatModel{
				{
					Assets: []common.Asset{
						{ID: "a1", DisplayName: "A1", Type: common.AssetTypeApplication},
					},
				},
				{
					Assets: []common.Asset{
						{ID: "a2", DisplayName: "A2", Type: common.AssetTypeWebserver},
					},
				},
			},
			expected: common.ThreatModel{
				Assets: []common.Asset{
					{ID: "a1", DisplayName: "A1", Type: common.AssetTypeApplication},
					{ID: "a2", DisplayName: "A2", Type: common.AssetTypeWebserver},
				},
				Extra: map[string]any{},
			},
		},
	}

	// Save the real functions so we can restore them after the test
	originalFuncStr := getUserInputAsText
	defer func() { getUserInputAsText = originalFuncStr }()

	originalFuncInt := getUserInputAsUnsignedInt
	defer func() { getUserInputAsUnsignedInt = originalFuncInt }()

	// Overwrite the global functions with our mocks
	getUserInputAsText = func() (string, error) {
		return "n", nil // dont accept automerge
	}

	getUserInputAsUnsignedInt = func() (uint, error) {
		return 0, nil //always select first option
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merger := NewModelMerger(dummyChangelog{}, slog.Default(), true)
			result := merger.Merge(tt.input)

			// Compare assets (ignore order)
			assert.ElementsMatch(t, tt.expected.Assets, result.Assets)

			// Compare extra fields
			assert.Equal(t, tt.expected.Extra, result.Extra)
		})
	}
}

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
			assets: mergeableAssets{
				{DisplayName: "DockerName", Source: common.DataSourceDockerCompose},
				{DisplayName: "ThreatName", Source: common.DataSourceThreatDragon},
			},
			expected: "ThreatName",
		},
		{
			name: "DockerCompose takes fallback when no ThreatDragon",
			assets: mergeableAssets{
				{DisplayName: "DockerName", Source: common.DataSourceDockerCompose},
				{DisplayName: "UnknownName", Source: common.DataSourceUnknown},
			},
			expected: "DockerName",
		},
		{
			name: "Unknown used when no higher priority",
			assets: mergeableAssets{
				{DisplayName: "UnknownName", Source: common.DataSourceUnknown},
			},
			expected: "UnknownName",
		},
		{
			name: "No matching source results in empty string",
			assets: mergeableAssets{
				{DisplayName: "Merged", Source: common.DataSourceMerged},
			},
			expected: "",
		},
		{
			name:     "Empty input returns empty string",
			assets:   mergeableAssets{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assets.displayName(slog.Default())
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
			assets: mergeableAssets{
				{Type: common.AssetTypeWebserver, Source: common.DataSourceDockerCompose},
				{Type: common.AssetTypeDatabase, Source: common.DataSourceThreatDragon},
			},
			expected: common.AssetTypeWebserver,
		},
		{
			name: "ThreatDragon used if no DockerCompose",
			assets: mergeableAssets{
				{Type: common.AssetTypeApplication, Source: common.DataSourceThreatDragon},
				{Type: common.AssetTypeWebserver, Source: common.DataSourceUnknown},
			},
			expected: common.AssetTypeApplication,
		},
		{
			name: "Unknown used if no preferred source",
			assets: mergeableAssets{
				{Type: common.AssetTypeDatabase, Source: common.DataSourceUnknown},
			},
			expected: common.AssetTypeDatabase,
		},
		{
			name: "No matching source results in AssetTypeUnknown",
			assets: mergeableAssets{
				{Type: common.AssetTypeApplication, Source: common.DataSourceMerged},
			},
			expected: common.AssetTypeUnknown,
		},
		{
			name:     "Empty input returns AssetTypeUnknown",
			assets:   mergeableAssets{},
			expected: common.AssetTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.assets.assetType(slog.Default())
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
			assets: mergeableAssets{
				{Extra: map[string]any{"a": 1, "b": 2}},
				{Extra: map[string]any{"c": 3}},
			},
			expected: map[string]any{"a": 1, "b": 2, "c": 3},
		},
		{
			name: "Later keys overwrite earlier keys",
			assets: mergeableAssets{
				{Extra: map[string]any{"key": "first"}},
				{Extra: map[string]any{"key": "second"}},
			},
			expected: map[string]any{"key": "second"},
		},
		{
			name: "Handles empty extra maps gracefully",
			assets: mergeableAssets{
				{Extra: map[string]any{}},
				{Extra: map[string]any{"x": true}},
			},
			expected: map[string]any{"x": true},
		},
		{
			name:     "Empty input returns empty map",
			assets:   mergeableAssets{},
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
			assets: mergeableAssets{
				{
					ID:          "a1",
					DisplayName: "App",
					Type:        common.AssetTypeApplication,
					Source:      common.DataSourceThreatDragon,
					Extra:       map[string]any{"foo": "bar"},
				},
			},
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
			assets: mergeableAssets{
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
				},
			},
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
			assets:    mergeableAssets{},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				assert.Panics(t, func() {
					_ = tt.assets.merge(slog.Default())
				})
			} else {
				result := tt.assets.merge(slog.Default())
				assert.Equal(t, tt.expected.ID, result.ID)
				assert.Equal(t, tt.expected.DisplayName, result.DisplayName)
				assert.Equal(t, tt.expected.Type, result.Type)
				assert.Equal(t, tt.expected.Source, result.Source)
				assert.Equal(t, tt.expected.Extra, result.Extra)
			}
		})
	}
}

func TestModelMerger_Merge(t *testing.T) {
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
						DisplayName: "From ThreatDragon",       // priority: ThreatDragon
						Type:        common.AssetTypeWebserver, // priority: DockerCompose
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			merger := NewModelMerger(dummyChangelog{}, slog.Default())
			result := merger.Merge(tt.input)

			// Compare assets (ignore order)
			assert.ElementsMatch(t, tt.expected.Assets, result.Assets)

			// Compare extra fields
			assert.Equal(t, tt.expected.Extra, result.Extra)
		})
	}
}

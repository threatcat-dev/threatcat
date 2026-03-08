package modelmerger

import (
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

func TestAllElementsEqual(t *testing.T) {
	type User struct {
		ID   int
		Name string
	}

	tests := []struct {
		name     string
		testFn   func() bool // Closure to capture the generic call
		expected bool
	}{
		{
			name: "Equal Integers",
			testFn: func() bool {
				return allElementsEqual([]int{1, 1, 1})
			},
			expected: true,
		},
		{
			name: "Unequal Strings",
			testFn: func() bool {
				return allElementsEqual([]string{"apple", "orange"})
			},
			expected: false,
		},
		{
			name: "Equal Structs",
			testFn: func() bool {
				u1 := User{ID: 1, Name: "Alice"}
				u2 := User{ID: 1, Name: "Alice"}
				return allElementsEqual([]User{u1, u2})
			},
			expected: true,
		},
		{
			name: "Unequal Structs",
			testFn: func() bool {
				return allElementsEqual([]User{
					{ID: 1, Name: "Alice"},
					{ID: 2, Name: "Bob"},
				})
			},
			expected: false,
		},
		{
			name: "Empty Struct Slice",
			testFn: func() bool {
				return allElementsEqual([]User{})
			},
			expected: true,
		},
		{
			name: "Single element returns true",
			testFn: func() bool {
				return allElementsEqual([]int{42})
			},
			expected: true,
		},
		{
			name: "First two equal, third different",
			testFn: func() bool {
				return allElementsEqual([]int{1, 1, 2})
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.testFn(); got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGroupByID(t *testing.T) {
	type User struct {
		ID   string
		Name string
	}

	tests := []struct {
		name     string
		items    []User
		getID    func(User) string
		expected map[string][]User
	}{
		{
			name:  "Groups multiple items by same ID",
			items: []User{{ID: "1", Name: "Alice"}, {ID: "1", Name: "Bob"}, {ID: "2", Name: "Charlie"}},
			getID: func(u User) string { return u.ID },
			expected: map[string][]User{
				"1": {{ID: "1", Name: "Alice"}, {ID: "1", Name: "Bob"}},
				"2": {{ID: "2", Name: "Charlie"}},
			},
		},
		{
			name:     "Returns empty map for nil or empty slice",
			items:    []User{},
			getID:    func(u User) string { return u.ID },
			expected: map[string][]User{},
		},
		{
			name:  "Groups by Name instead of ID",
			items: []User{{ID: "1", Name: "Alice"}, {ID: "2", Name: "Alice"}},
			getID: func(u User) string { return u.Name },
			expected: map[string][]User{
				"Alice": {{ID: "1", Name: "Alice"}, {ID: "2", Name: "Alice"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groupByID(tt.items, tt.getID)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("GroupByID() = %v, want %v", got, tt.expected)
			}
		})
	}
}
func TestGetHighestPriorityItemFromSlice(t *testing.T) {

	nDocker := "DockerName"
	nThreat := "ThreatName"
	nUnknown := "UnknownName"

	// test function with different Slices
	asset, retAs := getHighestPriorityItemFromSlice(
		[]common.Asset{
			{
				DisplayName: nDocker,
				Source:      common.DataSourceDockerCompose,
			},
			{
				DisplayName: nUnknown,
				Source:      common.DataSourceUnknown,
			},
		},
		map[common.DataSource]int{
			common.DataSourceDockerCompose: 0,
			common.DataSourceUnknown:       1,
		},
		func(asset common.Asset) common.DataSource { return asset.Source },
	)

	df, retDf := getHighestPriorityItemFromSlice(
		[]common.DataFlow{
			{
				Name:       nThreat,
				DataSource: common.DataSourceThreatDragon,
			},
			{
				Name:       nDocker,
				DataSource: common.DataSourceDockerCompose,
			},
		},
		map[common.DataSource]int{
			common.DataSourceThreatDragon:  0,
			common.DataSourceDockerCompose: 1,
		},
		func(df common.DataFlow) common.DataSource { return df.DataSource },
	)

	tb, retTb := getHighestPriorityItemFromSlice(
		[]common.TrustBoundary{
			{
				DisplayName: nUnknown,
				Source:      common.DataSourceUnknown,
			},
			{
				DisplayName: nThreat,
				Source:      common.DataSourceThreatDragon,
			},
		},
		map[common.DataSource]int{
			common.DataSourceDockerCompose: 0,
			common.DataSourceUnknown:       1,
			common.DataSourceThreatDragon:  2,
		},
		func(tb common.TrustBoundary) common.DataSource { return tb.Source },
	)

	//negative test with empty slice
	_, retZ := getHighestPriorityItemFromSlice(
		[]common.TrustBoundary{},
		map[common.DataSource]int{
			common.DataSourceDockerCompose: 0,
			common.DataSourceUnknown:       1,
			common.DataSourceThreatDragon:  2,
		},
		func(tb common.TrustBoundary) common.DataSource { return tb.Source },
	)

	//confirm that the element with highest prio is chosen every time
	assert.Equal(t, asset.DisplayName, nDocker)
	assert.Equal(t, asset.Source, common.DataSourceDockerCompose)
	assert.True(t, retAs)

	assert.Equal(t, df.Name, nThreat)
	assert.Equal(t, df.DataSource, common.DataSourceThreatDragon)
	assert.True(t, retDf)

	assert.Equal(t, tb.DisplayName, nUnknown)
	assert.Equal(t, tb.Source, common.DataSourceUnknown)
	assert.True(t, retTb)

	// confirm that funcion failed with invalid slice
	assert.False(t, retZ)

}

func TestGetHighestPrioValue(t *testing.T) {
	// Simple struct for testing
	type mockItem struct {
		Name   string
		Source common.DataSource
	}

	// Priority Map: DataSourceDockerCompose (0) >DataSourceThreatDragon (1)
	prioMap := map[common.DataSource]int{
		common.DataSourceDockerCompose: 0,
		common.DataSourceThreatDragon:  1,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name          string
		items         []mockItem
		defaultReturn []string
		want          string
	}{
		{
			name: "Selects highest priority (SourceA over SourceB)",
			items: []mockItem{
				{Name: "ItemB", Source: common.DataSourceThreatDragon},
				{Name: "ItemA", Source: common.DataSourceDockerCompose},
			},
			want: "ItemA",
		},
		{
			name: "Falls back to first item when no source matches priority map",
			items: []mockItem{
				{Name: "Unknown1", Source: common.DataSourceUnknown},
				{Name: "Unknown2", Source: common.DataSourceUnknown},
			},
			want: "Unknown1",
		},
		{
			name: "Falls back to provided defaultReturn when no priority match found",
			items: []mockItem{
				{Name: "Unknown1", Source: common.DataSourceUnknown},
			},
			defaultReturn: []string{"DefaultValue"},
			want:          "DefaultValue",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getHighestPrioValue(
				tt.items,
				prioMap,
				func(i mockItem) common.DataSource { return i.Source },
				func(i mockItem) string { return i.Name },
				logger,
				"success",
				"fallback",
				tt.defaultReturn...,
			)

			if got != tt.want {
				t.Errorf("getHighestPrioValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

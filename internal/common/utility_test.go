package common

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ptrStruct struct {
	ptr            *string
	innerPtrStruct *innerPtrStruct
}

type innerPtrStruct struct {
	inner *string
}

// TestGenerateIDHash verifies that GenerateIDHash produces consistent, deterministic
// hashes with correct length for various input combinations.
//
// Test cases:
//   - Valid file path and service name (typical use case)
//   - Empty file path and service name (edge case)
//   - Long file path and service name (stress test)
//
// Assertions:
//   - Hash is not empty for all input combinations
//   - Hash length equals MaxIDHashLength (32 characters)
//   - Hash is deterministic: same input produces identical output
//
// This test ensures the ID generation is reliable and consistent across calls,
// which is critical for tracking assets and data flows in threat models.
func TestGenerateIDHash(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		serviceName string
	}{
		{
			name:        "Valid file path and service name",
			filePath:    "/path/to/docker-compose.yml",
			serviceName: "web",
		},
		{
			name:        "Empty file path and service name",
			filePath:    "",
			serviceName: "",
		},
		{
			name:        "Long file path and service name",
			filePath:    "/a/very/long/path/to/a/docker-compose/file/that/should/be/hashed",
			serviceName: "very-long-service-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := GenerateIDHashFromFilePath(tt.filePath, tt.serviceName)
			secondHash := GenerateIDHashFromFilePath(tt.filePath, tt.serviceName) // Generate a second hash for comparison
			assert.Equal(t, hash, secondHash, "Hashes should be equal for the same input")
			assert.NotEmpty(t, hash, "Hash should not be empty")
			assert.Equal(t, MaxIDHashLength, len(hash), fmt.Sprintf("Hash length should be %d characters", MaxIDHashLength))
		})
	}
}

func TestRectangleContains(t *testing.T) {
	rect := NewRectangle(100, 100, 100, 100)
	rectIsNotContained := NewRectangle(0, 0, 50, 50)
	rectIsContained := NewRectangle(110, 110, 50, 50)
	rectIsPartialyContained := NewRectangle(110, 110, 100, 100)

	assert.False(t, rect.Contains(rectIsNotContained))
	assert.False(t, rect.Contains(rectIsPartialyContained))
	assert.True(t, rect.Contains(rectIsContained))
	assert.True(t, rect.Contains(rect))
}

func TestPtrDeref(t *testing.T) {
	ptrString := "ptr"
	innerString := "inner"
	validPtr := ptrStruct{
		ptr: &ptrString,
		innerPtrStruct: &innerPtrStruct{
			inner: &innerString,
		},
	}
	invalidPtr := ptrStruct{
		ptr: nil,
		innerPtrStruct: &innerPtrStruct{
			inner: nil,
		},
	}

	assert.Equal(t, ptrString, PtrDeref(validPtr.ptr))
	assert.Equal(t, innerString, PtrDeref(validPtr.innerPtrStruct.inner))
	assert.Equal(t, "", PtrDeref(invalidPtr.ptr))
	assert.Equal(t, "", PtrDeref(invalidPtr.innerPtrStruct.inner))
}

func TestPtrDerefDoubeled(t *testing.T) {
	invalidPtr := ptrStruct{
		innerPtrStruct: nil,
	}

	assert.Equal(t, "", PtrDeref(PtrDeref(invalidPtr.innerPtrStruct).inner))
}

func TestPtrDerefOr(t *testing.T) {
	ptrString := "ptr"
	innerString := "inner"
	validPtr := ptrStruct{
		ptr: &ptrString,
		innerPtrStruct: &innerPtrStruct{
			inner: &innerString,
		},
	}
	invalidPtr := ptrStruct{
		ptr: nil,
		innerPtrStruct: &innerPtrStruct{
			inner: nil,
		},
	}

	assert.Equal(t, ptrString, PtrDerefOr(validPtr.ptr, ""))
	assert.Equal(t, innerString, PtrDerefOr(validPtr.innerPtrStruct.inner, ""))
	assert.Equal(t, "alt1", PtrDerefOr(invalidPtr.ptr, "alt1"))
	assert.Equal(t, "alt2", PtrDerefOr(invalidPtr.innerPtrStruct.inner, "alt2"))
}

func TestPtrDerefOrDoubeled(t *testing.T) {
	invalidPtr := ptrStruct{
		innerPtrStruct: nil,
	}

	innerPtr := innerPtrStruct{}

	assert.Nil(t, innerPtr.inner)
	assert.Equal(t, "", PtrDerefOr(PtrDerefOr(invalidPtr.innerPtrStruct, innerPtr).inner, ""))
}

func TestFilter(t *testing.T) {
	start := []int{1, 2, 3, 4, 5}

	filterd := Filter(start, func(i int) bool {
		return i > 2
	})

	assert.Equal(t, 5, len(start), "length changed, but list arg should not be modified")
	assert.Equal(t, 3, len(filterd), "length of output should be 3 according to the filter")
}

// TestThreatTypeString verifies that the String() method for ThreatType enum
// returns correct string representations for all STRIDE threat types.
//
// Test cases:
//   - All 6 valid STRIDE threat types (Spoofing, Tampering, etc.)
//   - ThreatTypeUnknown (default value)
//   - Invalid enum value (999) should fall back to "ThreatTypeUnknown"
//
// Assertions:
//   - Each threat type returns its expected string representation
//   - Invalid values are handled gracefully with fallback string
//
// This ensures proper string conversion for logging, serialization, and display.
func TestThreatTypeString(t *testing.T) {
	tests := []struct {
		threatType ThreatType
		expected   string
	}{
		{Spoofing, "Spoofing"},
		{Tampering, "Tampering"},
		{Repudiation, "Repudiation"},
		{InformationDisclosure, "Information disclosure"},
		{DenialOfService, "Denial of service"},
		{ElevationOfPrivilege, "Elevation of privilege"},
		{ThreatTypeUnknown, "ThreatTypeUnknown"},
		{ThreatType(999), "ThreatTypeUnknown"}, // Invalid enum value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.threatType.String())
		})
	}
}

// TestParseThreatType verifies that ParseThreatType correctly converts string
// representations back to ThreatType enum values.
//
// Test cases:
//   - All 6 valid STRIDE threat type strings
//   - Invalid string ("invalid")
//   - Empty string
//
// Assertions:
//   - Valid strings are parsed to correct ThreatType enum values
//   - Invalid and empty strings return ThreatTypeUnknown
//
// This is the inverse operation of ThreatType.String() and is used for
// deserializing threat models from external formats.
func TestParseThreatType(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatType
	}{
		{"Spoofing", Spoofing},
		{"Tampering", Tampering},
		{"Repudiation", Repudiation},
		{"Information disclosure", InformationDisclosure},
		{"Denial of service", DenialOfService},
		{"Elevation of privilege", ElevationOfPrivilege},
		{"invalid", ThreatTypeUnknown},
		{"", ThreatTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseThreatType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestModelTypeString verifies that the String() method for ModelType enum
// returns correct string representations.
//
// Test cases:
//   - STRIDE (currently the only supported model type)
//   - NotSupported (for unsupported model types)
//   - Invalid enum value (999) should fall back to "NotSupported"
//
// Assertions:
//   - Each model type returns its expected string representation
//   - Invalid values default to "NotSupported"
func TestModelTypeString(t *testing.T) {
	tests := []struct {
		modelType ModelType
		expected  string
	}{
		{STRIDE, "STRIDE"},
		{NotSupported, "NotSupported"},
		{ModelType(999), "NotSupported"}, // Invalid enum value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.modelType.String())
		})
	}
}

// TestParseModelType verifies that ParseModelType correctly converts string
// representations to ModelType enum values.
//
// Test cases:
//   - "STRIDE" (valid model type)
//   - "invalid" (unsupported model type)
//   - Empty string
//
// Assertions:
//   - "STRIDE" is parsed correctly
//   - Invalid and empty strings return NotSupported
//
// This function is used when parsing threat model metadata from external sources.
func TestParseModelType(t *testing.T) {
	tests := []struct {
		input    string
		expected ModelType
	}{
		{"STRIDE", STRIDE},
		{"invalid", NotSupported},
		{"", NotSupported},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseModelType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestStatusString verifies that the String() method for Status enum returns
// correct string representations for all threat status values.
//
// Test cases:
//   - Open (threat identified but not addressed)
//   - Mitigated (threat has been resolved)
//   - NotApplicable (threat doesn't apply)
//   - UnknownStatus (status not specified)
//   - Invalid enum value (999) should fall back to "UnknownStatus"
//
// Assertions:
//   - Each status returns its expected string representation
//   - Invalid values are handled with fallback string
func TestStatusString(t *testing.T) {
	tests := []struct {
		status   Status
		expected string
	}{
		{Open, "Open"},
		{Mitigated, "Mitigated"},
		{NotApplicable, "Not Applicable"},
		{UnknownStatus, "UnknownStatus"},
		{Status(999), "UnknownStatus"}, // Invalid enum value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

// TestParseStatus verifies that ParseStatus correctly converts string
// representations to Status enum values.
//
// Test cases:
//   - All 3 valid status strings ("Open", "Mitigated", "Not Applicable")
//   - Invalid string ("invalid")
//   - Empty string
//
// Assertions:
//   - Valid strings are parsed to correct Status values
//   - Invalid and empty strings return UnknownStatus
//
// This is used when deserializing threat status from saved threat models.
func TestParseStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected Status
	}{
		{"Open", Open},
		{"Mitigated", Mitigated},
		{"Not Applicable", NotApplicable},
		{"invalid", UnknownStatus},
		{"", UnknownStatus},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseStatus(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAssetTypeString verifies that the String() method for AssetType enum
// returns correct string representations for all asset types.
//
// Test cases:
//   - All 4 specific asset types (Application, Database, Webserver, Infrastructure)
//   - AssetTypeUnknown (default/unspecified)
//   - Invalid enum value (999) should fall back to "AssetTypeUnknown"
//
// Assertions:
//   - Each asset type returns its expected string representation
//   - Invalid values default to "AssetTypeUnknown"
//
// Asset types are used to categorize components in the threat model.
func TestAssetTypeString(t *testing.T) {
	tests := []struct {
		assetType AssetType
		expected  string
	}{
		{AssetTypeApplication, "AssetTypeApplication"},
		{AssetTypeDatabase, "AssetTypeDatabase"},
		{AssetTypeWebserver, "AssetTypeWebserver"},
		{AssetTypeInfrastructure, "AssetTypeInfrastructure"},
		{AssetTypeUnknown, "AssetTypeUnknown"},
		{AssetType(999), "AssetTypeUnknown"}, // Invalid enum value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.assetType.String())
		})
	}
}

// TestDataSourceShortString verifies that the ShortString() method for DataSource enum
// returns human-readable short names for all data sources.
//
// Test cases:
//   - DataSourceUnknown → "Unknown"
//   - DataSourceThreatDragon → "Threat Dragon"
//   - DataSourceDockerCompose → "Docker Compose"
//   - DataSourceMerged → "Merged"
//   - Invalid enum value (999) → "Unknown"
//
// Assertions:
//   - Each data source returns its expected short string
//   - Invalid values default to "Unknown"
//
// Short strings are used for display in logs, UI, and error messages.
func TestDataSourceShortString(t *testing.T) {
	tests := []struct {
		source   DataSource
		expected string
	}{
		{DataSourceUnknown, "Unknown"},
		{DataSourceThreatDragon, "Threat Dragon"},
		{DataSourceDockerCompose, "Docker Compose"},
		{DataSourceMerged, "Merged"},
		{DataSource(999), "Unknown"}, // Invalid enum value
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.source.ShortString())
		})
	}
}

// TestGet verifies the generic Get function for type-safe map value retrieval.
//
// Test cases:
//   - Successful string retrieval from map
//   - Successful int retrieval from map
//   - Key not found error
//   - Type cast failure (wrong type specified)
//   - Nil map handling
//
// Assertions:
//   - Correct values are returned for valid key and type combinations
//   - ErrMapKeyNotFound is returned when key doesn't exist
//   - ErrTypeCastFailed is returned when type assertion fails
//   - Nil maps are handled gracefully with appropriate error
//
// This generic function provides type-safe access to map[string]any,
// commonly used for Extra metadata in threat model structures.
func TestGet(t *testing.T) {
	testMap := map[string]any{
		"string": "value",
		"int":    42,
		"bool":   true,
		"float":  3.14,
	}

	t.Run("Successful string retrieval", func(t *testing.T) {
		result, err := Get[string](testMap, "string")
		require.NoError(t, err)
		assert.Equal(t, "value", result)
	})

	t.Run("Successful int retrieval", func(t *testing.T) {
		result, err := Get[int](testMap, "int")
		require.NoError(t, err)
		assert.Equal(t, 42, result)
	})

	t.Run("Key not found", func(t *testing.T) {
		_, err := Get[string](testMap, "missing")
		assert.ErrorIs(t, err, ErrMapKeyNotFound)
	})

	t.Run("Type cast failed", func(t *testing.T) {
		_, err := Get[int](testMap, "string")
		assert.ErrorIs(t, err, ErrTypeCastFailed)
	})

	t.Run("Nil map", func(t *testing.T) {
		_, err := Get[string](nil, "key")
		assert.ErrorIs(t, err, ErrMapKeyNotFound)
	})
}

// TestGetOr verifies the generic GetOr function with fallback values.
// This is a safer alternative to Get that never returns an error.
//
// Test cases:
//   - Successful retrieval returns actual value
//   - Key not found returns alternative value
//   - Type cast failure returns alternative value
//   - Nil map returns alternative value
//
// Assertions:
//   - When key exists and type matches, actual value is returned
//   - In all error cases, the provided alternative is returned
//   - No errors are ever returned (error-free API)
//
// Use this when you want default values instead of error handling.
func TestGetOr(t *testing.T) {
	testMap := map[string]any{
		"string": "value",
		"int":    42,
	}

	t.Run("Successful retrieval", func(t *testing.T) {
		result := GetOr(testMap, "string", "default")
		assert.Equal(t, "value", result)
	})

	t.Run("Key not found returns alternative", func(t *testing.T) {
		result := GetOr(testMap, "missing", "default")
		assert.Equal(t, "default", result)
	})

	t.Run("Type cast failed returns alternative", func(t *testing.T) {
		result := GetOr(testMap, "string", 999)
		assert.Equal(t, 999, result)
	})

	t.Run("Nil map returns alternative", func(t *testing.T) {
		result := GetOr[string](nil, "key", "default")
		assert.Equal(t, "default", result)
	})
}

// TestEmptyThreatModel verifies the EmptyThreatModel constructor creates
// a properly initialized empty threat model.
//
// Test scenario:
//   - Calls EmptyThreatModel() to create a new instance
//   - Checks initialization of all fields
//
// Assertions:
//   - Assets slice is initialized and empty (not nil)
//   - DataFlows slice is initialized and empty (not nil)
//   - Boundaries is explicitly nil
//   - Extra map is initialized and empty (not nil)
//
// Proper initialization prevents nil pointer panics when adding elements
// to a new threat model.
func TestEmptyThreatModel(t *testing.T) {
	model := EmptyThreatModel()

	assert.NotNil(t, model.Assets)
	assert.Empty(t, model.Assets)
	assert.NotNil(t, model.DataFlows)
	assert.Empty(t, model.DataFlows)
	assert.Nil(t, model.Boundaries)
	assert.NotNil(t, model.Extra)
	assert.Empty(t, model.Extra)
}


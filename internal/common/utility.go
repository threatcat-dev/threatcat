// Package common provides core data models and utilities for threat modeling.
// It defines the fundamental types used across the threat modeling tool, including
// ThreatModel, Asset, DataFlow, and associated enumerations.
package common

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Sentinel errors for map operations and type assertions.
var (
	ErrMapKeyNotFound = errors.New("map does not contain the requested key")
	ErrTypeCastFailed = errors.New("type assertion failed for the requested type")
	ErrEmptyInput     = errors.New("input cannot be empty")
)

// Rectangle represents a rectangular area defined by its position (Left, Top)
// and dimensions (Width, Height).
// Left and Top define the upper-left corner position.
// Width and Height define the size of the rectangle.
// All values are in floating-point coordinates.
type Rectangle struct {
	Height float64
	Left   float64
	Top    float64
	Width  float64
}

// NewRectangle creates a new Rectangle instance with the specified position and dimensions.
// Parameters:
//   - left: the x-coordinate of the upper-left corner
//   - top: the y-coordinate of the upper-left corner
//   - width: the horizontal extent of the rectangle
//   - height: the vertical extent of the rectangle
//
// Returns a pointer to the newly created Rectangle.
func NewRectangle(left float64, top float64, width float64, height float64) *Rectangle {
	return &Rectangle{
		Height: height,
		Left:   left,
		Top:    top,
		Width:  width,
	}
}

// Contains checks if Rectangle r fully contains Rectangle other.
// A rectangle is considered contained if all four corners of other are within or on the boundaries
// of r.
//
// Parameters:
//   - other: the rectangle to check containment of
//
// Returns true if other is fully contained within r, false otherwise.
func (r *Rectangle) Contains(other *Rectangle) bool {
	isXContained := (r.Left <= other.Left) && ((r.Left + r.Width) >= (other.Left + other.Width))
	isYContained := (r.Top <= other.Top) && ((r.Top + r.Height) >= (other.Top + other.Height))

	return (isXContained && isYContained)
}

// Filter returns a new slice of type T, containing all items from list for which filterFunc returns true.
func Filter[T any](list []T, filter func(T) bool) []T {
	filtered := make([]T, 0, len(list))
	for _, item := range list {
		if filter(item) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

// PtrDeref dereferences a pointer that may be nil. If pointer is nil, returns the zero value.
// This does not work if there are multiple dereferences; in that case use PtrDeref as argument to itself.
func PtrDeref[T any](ptr *T) T {
	if ptr != nil {
		return *ptr
	}
	var zero T
	return zero
}

// PtrDerefOr dereferences a pointer that may be nil. If pointer is nil, returns the alternative.
// This does not work if there are multiple dereferences; in that case use PtrDerefOr as argument to itself.
func PtrDerefOr[T any](ptr *T, alternative T) T {
	if ptr != nil {
		return *ptr
	}
	return alternative
}

// Get retrieves a value of type T from the provided map using the specified key.
//
// Parameters:
//   - extraMap: the map to retrieve the value from (may be nil)
//   - key: the key to look up in the map
//
// Returns:
//   - The value of type T if found and successfully cast
//   - ErrMapKeyNotFound if the map is nil or the key doesn't exist
//   - ErrTypeCastFailed if the value exists but cannot be cast to type T
func Get[T any](extraMap map[string]any, key string) (T, error) {
	var zero T

	if extraMap == nil {
		return zero, ErrMapKeyNotFound
	}

	value, ok := extraMap[key]
	if !ok {
		return zero, ErrMapKeyNotFound
	}

	assertedValue, ok := value.(T)
	if !ok {
		return zero, ErrTypeCastFailed
	}

	return assertedValue, nil
}

// GetOr retrieves a value of type T from the provided map using the specified key.
// If the key is not found, the map is nil, or the type assertion fails,
// it returns the provided alternative value.
//
// Parameters:
//   - extraMap: the map to retrieve the value from (may be nil)
//   - key: the key to look up in the map
//   - alternative: the fallback value to return if retrieval fails
//
// Returns the retrieved value if successful, otherwise returns alternative.
// This function never returns an error.
func GetOr[T any](extraMap map[string]any, key string, alternative T) T {
	if extraMap == nil {
		return alternative
	}

	value, ok := extraMap[key]
	if !ok {
		return alternative
	}

	assertedValue, ok := value.(T)
	if !ok {
		return alternative
	}

	return assertedValue
}

// generateIDHash generates a unique ID hash from two given strings (e.g., file path and name).
// The hash is created using SHA-256 and truncated to MaxIDHashLength characters.
//
// Parameters:
//   - s1: the first string to include in the hash (may be empty)
//   - s2: the second string to include in the hash (may be empty)
//
// Returns a hexadecimal string of length MaxIDHashLength.
// The function is deterministic: same inputs always produce the same output.
// Both empty s1 and s2 are allowed, resulting in a hash of empty string.
func generateIDHash(s1 string, s2 string) string {
	hasher := sha256.New()
	hasher.Write([]byte(s1 + s2))
	return hex.EncodeToString(hasher.Sum(nil))[:MaxIDHashLength]
}

// GenerateIDHashFromFilePath generates a unique ID hash from a file path and name.
func GenerateIDHashFromFilePath(filePath string, name string) string {
	return generateIDHash(filePath, name)
}

// GenerateIDHashFromEntityNames generates a unique ID hash from two entity names (e.g., asset names).
func GenerateIDHashFromEntityNames(entityName1 string, entityName2 string) string {
	return generateIDHash(entityName1, entityName2)
}

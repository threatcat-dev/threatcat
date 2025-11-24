package common

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var ErrKeyNotFound = errors.New("the map does not conatin the requested key")
var ErrCastFailed = errors.New("the requested cast on any type failed")

type Rectangle struct {
	Height float64
	Left   float64
	Top    float64
	Width  float64
}

func NewRectangle(left float64, top float64, width float64, height float64) *Rectangle {
	return &Rectangle{
		Height: height,
		Left:   left,
		Top:    top,
		Width:  width,
	}
}

func (r *Rectangle) IsContained(other *Rectangle) bool {
	isXContained := (r.Left >= other.Left) && ((r.Left + r.Width) <= (other.Left + other.Width))
	isYContained := (r.Top >= other.Top) && ((r.Top + r.Height) <= (other.Top + other.Height))

	return (isXContained && isYContained)
}

func Get[T any](extraMap map[string]any, key string) (T, error) {
	value, ok := extraMap[key]
	var zero T
	if !ok {
		return zero, ErrKeyNotFound
	}
	assetedValue, ok := value.(T)
	if !ok {
		return zero, ErrCastFailed
	}
	return assetedValue, nil
}

func GetOr[T any](extraMap map[string]any, key string, alternative T) T {
	value, ok := extraMap[key]
	if !ok {
		return alternative
	}
	assetedValue, ok := value.(T)
	if !ok {
		return alternative
	}
	return assetedValue
}

// generateIDHash generates a unique ID hash for a given file path and name
func GenerateIDHash(filePath, name string) string {
	hasher := sha256.New()
	hasher.Write([]byte(filePath + name))
	return hex.EncodeToString(hasher.Sum(nil))[:MaxIDHashLength]
}

package common

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

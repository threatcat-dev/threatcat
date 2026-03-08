package modelmerger

import (
	"log/slog"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// allElementsEqual checks if all elements in a slice are equal to each other.
//
// Parameters:
//   - arr: the slice to check (may be empty or nil)
//
// Returns:
//   - true if all elements are equal (comparison using ==)
//   - true for empty or nil slices
//   - false if any element differs from the first element
func allElementsEqual[T comparable](arr []T) bool {
	if len(arr) == 0 {
		return true
	}
	first := arr[0]
	for _, v := range arr[1:] {
		if v != first {
			return false
		}
	}
	return true
}

// groupByID organizes a slice of items into a map keyed by a unique identifier.
func groupByID[T any](items []T, getID func(T) string) map[string][]T {
	m := make(map[string][]T)
	for _, item := range items {
		id := getID(item)
		m[id] = append(m[id], item)
	}
	return m
}

// getHighestPriorityItemFromSlice performs a search through a slice to find the item
// with the highest priority based on a provided priority map.
//
// Parameters:
//   - items: The slice of elements to search through.
//   - priorityMap: A map where keys are the source identifiers and values are
//     rankings (lower integers represent higher priority, e.g., 0 is highest).
//   - getSource: A selector function that extracts the source identifier from an item.
//
// Returns:
//   - The item with the highest priority found.
//   - A boolean indicating if any item from the slice was actually found in the priorityMap.
func getHighestPriorityItemFromSlice[T any, S comparable](
	items []T,
	priorityMap map[S]int,
	getSource func(T) S,
) (T, bool) {
	var bestItem T
	found := false
	bestPriority := len(priorityMap) + 1 // Start with a value worse than any possible priority

	for _, item := range items {
		source := getSource(item)

		// Check if this source is in our priority list
		if p, ok := priorityMap[source]; ok {
			// If it's a higher priority (lower number) than what we have, save it
			if p < bestPriority {
				bestPriority = p
				bestItem = item
				found = true
			}
			// If it's the absolute top priority (0), we can stop early
			if p == 0 {
				return item, true
			}
		}
	}

	return bestItem, found
}

// getHighestPrioValue selects the highest priority value from a slice based on a priority map.
//
// Selection: Returns getResult of the item with the lowest rank in priorityMap.
// Fallback: If no match is found, returns the first element of defaultReturn (if provided),
// otherwise returns getResult of items[0].
//
// Type Parameters:
//   - T: The type of the input items (e.g., common.DataFlow).
//   - R: The type of the final return value (e.g., string or the item itself).
func getHighestPrioValue[T any, R any](
	items []T,
	priorityMap map[common.DataSource]int,
	getSource func(T) common.DataSource,
	getResult func(T) R,
	logger *slog.Logger,
	logMsgSuccess string,
	logMsgFallback string,
	defaultReturn ...R,
) R {
	val, found := getHighestPriorityItemFromSlice(items, priorityMap, getSource)

	if found {
		logger.Debug(logMsgSuccess, "source", getSource(val).ShortString())
		return getResult(val)
	}

	// No item was found, return a default value
	logger.Debug(logMsgFallback)

	// Check if an optional default was provided
	if len(defaultReturn) > 0 {
		return defaultReturn[0]
	}

	// Standard fallback
	return getResult(items[0])
}

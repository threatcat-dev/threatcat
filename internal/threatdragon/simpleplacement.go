// This file implements a simple sequential placement strategy used as fallback when the solver fails.

package threatdragon

const defaultMaxWidth = 1000
const defaultOffsetX = 120
const defaultOffsetY = 50
const defaultBoundaryWidth = 120
const defaultBoundaryHeight = 60

// simplePlacement provides a basic sequential positioning strategy for diagram elements.
type simplePlacement struct {
	nextX    float64
	nextY    float64
	maxWidth float64
	offsetX  float64
	offsetY  float64
}

// newSimplePlacement initializes a new simplePlacement with default values.
func newSimplePlacement() *simplePlacement {
	return &simplePlacement{
		nextX:    50,
		nextY:    50,
		maxWidth: defaultMaxWidth,
		offsetX:  defaultOffsetX,
		offsetY:  defaultOffsetY,
	}
}

// determineStartingPoint calculates the initial position for new elements based on existing cells in the diagram.
func (sp *simplePlacement) determineStartingPoint(existingCells []Cell) {
	for _, existingCell := range existingCells {
		cellMaxX := 0.0
		cellMaxY := 0.0

		if isCurve(existingCell) {

		} else {
			cellMaxX = existingCell.Position.X + existingCell.Size.Width
			cellMaxY = existingCell.Position.Y + existingCell.Size.Height
		}

		if cellMaxX > sp.maxWidth {
			sp.maxWidth = cellMaxX
		}

		if cellMaxY+sp.offsetY > sp.nextY {
			sp.nextY = cellMaxY + sp.offsetY
		}
	}
}

// GetPosition returns the next available coordinates and updates internal state for the subsequent call.
func (sp *simplePlacement) GetPosition(_ string, _ float64, _ float64) (float64, float64, error) {
	x, y := sp.nextX, sp.nextY

	sp.nextX += sp.offsetX

	if sp.nextX > sp.maxWidth {
		sp.nextX = 0
		sp.nextY += sp.offsetY
	}

	return x, y, nil
}

// GetBoundaryPosition returns the coordinates and default dimensions for a new trust boundary.
func (sp *simplePlacement) GetBoundaryPosition(_ string) (float64, float64, float64, float64, error) {
	x, y, err := sp.GetPosition("", 0, 0)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	return x, y, defaultBoundaryWidth, defaultBoundaryHeight, nil
}

// dontPlace is a positioning strategy that always returns (0,0).
type dontPlace struct{}

// GetPosition returns (0,0,nil).
func (dp dontPlace) GetPosition(_ string, _ float64, _ float64) (float64, float64, error) {
	return 0, 0, nil
}

// GetBoundaryPosition returns (0,0,0,0,nil).
func (dp dontPlace) GetBoundaryPosition(_ string) (float64, float64, float64, float64, error) {
	return 0, 0, 0, 0, nil
}

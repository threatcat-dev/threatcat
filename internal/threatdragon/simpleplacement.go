package threatdragon

const defaultMaxWidth = 1000
const defaultOffsetX = 120
const defaultOffsetY = 50
const defaultBoundaryWidth = 120
const defaultBoundaryHeight = 60

type simplePlacement struct {
	nextX    float64
	nextY    float64
	maxWidth float64
	offsetX  float64
	offsetY  float64
}

func newSimplePlacement() *simplePlacement {
	return &simplePlacement{
		nextX:    50,
		nextY:    50,
		maxWidth: defaultMaxWidth,
		offsetX:  defaultOffsetX,
		offsetY:  defaultOffsetY,
	}
}

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

func (sp *simplePlacement) GetPosition(string) (float64, float64) {
	x, y := sp.nextX, sp.nextY

	sp.nextX += sp.offsetX

	if sp.nextX > sp.maxWidth {
		sp.nextX = 0
		sp.nextY += sp.offsetY
	}

	return x, y
}

func (sp *simplePlacement) GetBoundaryPosition(string) (float64, float64, float64, float64) {
	x, y := sp.GetPosition("")
	return x, y, defaultBoundaryWidth, defaultBoundaryHeight
}

type dontPlace struct{}

func (dp dontPlace) GetPosition(assetID string) (float64, float64) {
	return 0, 0
}

func (dp dontPlace) GetBoundaryPosition(boundaryID string) (float64, float64, float64, float64) {
	return 0, 0, 0, 0
}

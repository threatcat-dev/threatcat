package threatdragon

import (
	"log/slog"
)

// represents the coordinate system of a ThreatDragon diagram
// and provides functions to position cells within it.
type CoordinateSystem struct {
	// max width of the coordinate system
	width float64
	// min offset to the next cell in the coordinate system both horizontally and vertically
	offsetNextCell float64
	// height of the highest cell in the current row
	// used to determine where the next row starts
	maxHeightCurrentRow float64
	// position of next cell to be placed in the coordinate system
	// this is the top left corner of the cell
	positionNextCell VertexClass

	logger *slog.Logger
}

func NewCoordinateSystem(logger *slog.Logger) *CoordinateSystem {
	return &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 0.0,
		positionNextCell:    VertexClass{X: 0.0, Y: 0.0},
		logger:              logger.With("sub-component", "CoordinateSystem"),
	}

}

// method to determine the starting y axis coordinate for the positioning of generated cells
func (cs *CoordinateSystem) DetermineOffsetAndWidth(cell Cell) {
	cs.logger.Debug("Considering cell to adjust start row and width")
	if isCurve(cell) {
		sourceConnected := hasSourcePort(cell)
		targetConnected := hasTargetPort(cell)

		if sourceConnected && targetConnected {
			// if source and target are connected to other elements,
			// we can ignore them for DetermineStartRow, as the connected elements
			// will already be taken into account.
			return
		} else {
			if !sourceConnected {
				// the source only has coordinates, if it's not connected
				cs.updateStartRowIfLarger(float64(*cell.Source.Y))
				cs.updateWidthIfLarger(float64(*cell.Source.X))
			}
			if !targetConnected {
				// the target only has coordinates, if it's not connected
				cs.updateStartRowIfLarger(float64(*cell.Target.Y))
				cs.updateWidthIfLarger(float64(*cell.Target.X))
			}
		}
	} else {
		// if it's a cell, just use x+width or y+height respectively.
		cs.updateStartRowIfLarger(cell.Position.Y + cell.Size.Height)
		cs.updateWidthIfLarger(cell.Position.X + cell.Size.Width)
	}
}

// updateStartRowIfLarger updates the starting row of the coordinate system,
// but only if the given y coordinate + offset are larger than the current starting point.
func (cs *CoordinateSystem) updateStartRowIfLarger(y float64) {
	newStartRow := y + cs.offsetNextCell
	if newStartRow > cs.positionNextCell.Y {
		cs.logger.Debug("Starting row has been increased", "y", newStartRow)
		cs.positionNextCell.Y = newStartRow
	}
}

// updateWidthIfLarger updates the width of the coordinate system,
// but only if the given x coordinate is larger than the current width.
func (cs *CoordinateSystem) updateWidthIfLarger(x float64) {
	if x > cs.width {
		cs.logger.Debug("Width has been increased", "x", x)
		cs.width = x
	}
}

// method to position a cell within the coordinate system
func PositionCell(cs *CoordinateSystem, cell *Cell) {
	cs.logger.Info("Positioning a new cell/curve")
	widthNextCell := 0.0
	heightNextCell := 0.0
	isCurve := isCurve(*cell)

	// if the cell is a curve, the width and height are taken from the cell's width and height
	// otherwise, the width and height are taken from the cell's size
	if isCurve {
		widthNextCell = *cell.Width
		heightNextCell = *cell.Height
	} else {
		widthNextCell = cell.Size.Width
		heightNextCell = cell.Size.Height
	}

	// wrap to next row if the next cell's position plus the width of the next cell exceeds the width of the coordinate system
	if cs.positionNextCell.X+widthNextCell > cs.width {
		cs.positionNextCell.X = 0
		cs.positionNextCell.Y += cs.maxHeightCurrentRow + cs.offsetNextCell
		cs.maxHeightCurrentRow = 0
	}

	// update the maximum height of the current row if the cell's height exceeds it
	if heightNextCell > cs.maxHeightCurrentRow {
		cs.maxHeightCurrentRow = heightNextCell
	}

	setPosition(cs, cell, isCurve)
}

// setPosition sets the position of the cell in the coordinate system
// if the cell is a curve, it sets the source and target positions
func setPosition(cs *CoordinateSystem, cell *Cell, isCurve bool) {
	// if the cell is a curve, set the source and target positions
	// otherwise, set the position of the cell directly
	if isCurve {
		// set the source of the cell to the next cell's position
		*cell.Source.X = int64(cs.positionNextCell.X)
		*cell.Source.Y = int64(cs.positionNextCell.Y)
		// set the target of the cell to the next cell's position plus the width and height
		// this is used for data flows and boundary curves
		*cell.Target.X = int64(cs.positionNextCell.X + *cell.Width)
		*cell.Target.Y = int64(cs.positionNextCell.Y + *cell.Height)
		// update the next cell's position for the next iteration
		cs.positionNextCell.X += *cell.Width + cs.offsetNextCell
		cs.logger.Debug("Curve has been positioned", "source.X", *cell.Source.X, "source.Y", *cell.Source.Y, "target.X", *cell.Target.X, "target.Y", *cell.Target.Y)
	} else {
		// set the position of the cell to the next cell's position
		cell.Position.X = cs.positionNextCell.X
		cell.Position.Y = cs.positionNextCell.Y
		// update the next cell's position for the next iteration
		cs.positionNextCell.X += cell.Size.Width + cs.offsetNextCell
		cs.logger.Debug("Cell has been positioned", "x", cell.Position.X, "y", cell.Position.Y)
	}
}

// isCurve checks if the cell is a curve (data flow or boundary curve)
func isCurve(cell Cell) bool {
	return cell.Data.Type == "tm.Flow" || cell.Data.Type == "tm.Boundary"
}

// hasSourcePort checks if the curve cell's source is connected to a cell or port
func hasSourcePort(cell Cell) bool {
	return cell.Source.Cell != nil || cell.Source.Port != nil
}

// hasTargetPort checks if the curve cell's target is connected to a cell or port
func hasTargetPort(cell Cell) bool {
	return cell.Target.Cell != nil || cell.Target.Port != nil
}

package threatdragon

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDetermineStartRowForPositioningWithoutAdjustingY tests the DetermineStartRowForPositioning function
// by checking if it correctly adjusts the Y position of the next cell based on the current cell's position and size.
// In this case the Y position of the next cell is not adjusted, so it should remain the same as the initial value.
func TestDetermineStartRowWithoutAdjustingY(t *testing.T) {
	cs := &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 0.0,
		positionNextCell:    VertexClass{X: 0.0, Y: 500.0},
		logger:              slog.Default(),
	}

	process := Cell{
		Data: Data{
			Type: "tm.Process",
		},
		Position: &VertexClass{X: 0.0, Y: 370.0},
		Size:     &Size{Width: 60.0, Height: 60.0},
	}

	// Determine the start row for process
	cs.DetermineOffsetAndWidth(process)

	assert.Equal(t, 500.0, cs.positionNextCell.Y, "The Y position of the next cell should remain unchanged.")

	flow := Cell{
		Data: Data{
			Type: "tm.Flow",
		},
		Width:  float64Ptr(200.0),
		Height: float64Ptr(100.0),
		Source: &Source{X: int64Ptr(100), Y: int64Ptr(440)},
		Target: &Source{X: int64Ptr(0), Y: int64Ptr(0)},
	}

	// Determine the start row for flow
	cs.DetermineOffsetAndWidth(flow)

	assert.Equal(t, 500.0, cs.positionNextCell.Y, "The Y position of the next cell should remain unchanged.")
}

// TestDetermineStartRowForPositioningWithAdjustingY tests the DetermineStartRowForPositioning function
// by checking if it correctly adjusts the Y position of the next cell based on the current cell's position and size.
// In this case the Y position of the next cell is adjusted, so it should be set to the bottom of the current cell plus the offset.
func TestDetermineStartRowWithAdjustingY(t *testing.T) {
	cs := &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 0.0,
		positionNextCell:    VertexClass{X: 0.0, Y: 480.0},
		logger:              slog.Default(),
	}

	process := Cell{
		Data: Data{
			Type: "tm.Process",
		},
		Position: &VertexClass{X: 0.0, Y: 390.0},
		Size:     &Size{Width: 60.0, Height: 60.0},
	}

	// Determine the start row for process
	cs.DetermineOffsetAndWidth(process)

	assert.Equal(t, 500.0, cs.positionNextCell.Y, "The Y position of the next cell should be adjusted to the bottom of the currently highest cell plus the offset.")

	flow := Cell{
		Data: Data{
			Type: "tm.Flow",
		},
		Width:  float64Ptr(200.0),
		Height: float64Ptr(100.0),
		Source: &Source{X: int64Ptr(100), Y: int64Ptr(0)},
		Target: &Source{X: int64Ptr(0), Y: int64Ptr(480)},
	}

	// Determine the start row for flow
	cs.DetermineOffsetAndWidth(flow)

	assert.Equal(t, 530.0, cs.positionNextCell.Y, "The Y position of the next cell should be adjusted to the bottom of the currently highest cell plus the offset.")
}

func TestDetermineStartRowWithAdjustingMapWidth(t *testing.T) {
	cs := &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 0.0,
		positionNextCell:    VertexClass{X: 0.0, Y: 0.0},
		logger:              slog.Default(),
	}

	process := Cell{
		Data: Data{
			Type: "tm.Process",
		},
		Position: &VertexClass{X: 1100.0, Y: 0.0},
		Size:     &Size{Width: 120.0, Height: 80.0}, // Width exceeds the map width
	}

	// Determine the start row for process
	cs.DetermineOffsetAndWidth(process)

	assert.Equal(t, 130.0, cs.positionNextCell.Y, "The Y position of the next cell should be adjusted to the bottom of the currently highest cell plus the offset.")
	assert.Equal(t, 1220.0, cs.width, "The width of the map should be adjusted to the x coordinate of the cell plus the width of the cell.")

	flow := Cell{
		Data: Data{
			Type: "tm.Flow",
		},
		Width:  float64Ptr(200.0),
		Height: float64Ptr(100.0),
		Source: &Source{X: int64Ptr(100), Y: int64Ptr(460)},
		Target: &Source{X: int64Ptr(1300), Y: int64Ptr(300)},
	}

	// Determine the start row for flow
	cs.DetermineOffsetAndWidth(flow)

	assert.Equal(t, 510.0, cs.positionNextCell.Y, "The Y position of the next cell should be adjusted to the bottom of the currently highest cell plus the offset.")
	assert.Equal(t, 1300.0, cs.width, "The width of the map should be adjusted to the x coordinate of the cell plus the width of the cell.")
}

// TestPositionCellWithoutExceedingMapWidth tests the PositionCell function by checking if it correctly positions a cell
// within the coordinate system, adjusting the next cell's position and the maximum height of the current row.
func TestPositionCellWithoutExceedingMapWidth(t *testing.T) {
	cs := &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 80.0,
		positionNextCell:    VertexClass{X: 120.0, Y: 500.0}, // Width does not exceed the map width
		logger:              slog.Default(),
	}

	process := &Cell{
		Data: Data{
			Type: "tm.Process",
		},
		Position: &VertexClass{X: 0.0, Y: 0.0},
		Size:     &Size{Width: 60.0, Height: 60.0},
	}

	// Position the process cell
	PositionCell(cs, process)

	assert.Equal(t, 120.0, process.Position.X, "The X position of the cell should match the next cell's position.")
	assert.Equal(t, 500.0, process.Position.Y, "The Y position of the cell should match the next cell's position.")
	assert.Equal(t, 230.0, cs.positionNextCell.X, "The X position of the next cell should be updated correctly.")
	assert.Equal(t, 500.0, cs.positionNextCell.Y, "The Y position of the next cell should remain unchanged.")
	assert.Equal(t, 80.0, cs.maxHeightCurrentRow, "The maximum height of the current row should remain unchanged.")

	flow := &Cell{
		Data: Data{
			Type: "tm.Flow",
		},
		Width:  float64Ptr(200.0),
		Height: float64Ptr(100.0),
		Source: &Source{X: int64Ptr(0), Y: int64Ptr(0)},
		Target: &Source{X: int64Ptr(0), Y: int64Ptr(0)},
	}

	// Position the flow cell
	PositionCell(cs, flow)

	assert.Equal(t, 230, int(*flow.Source.X), "The X position of the flow source should match the next cell's position.")
	assert.Equal(t, 500, int(*flow.Source.Y), "The Y position of the flow source should match the next cell's position.")
	assert.Equal(t, 430, int(*flow.Target.X), "The X position of the flow target should be the source position plus the width of the flow.")
	assert.Equal(t, 600, int(*flow.Target.Y), "The Y position of the flow target should be the source position plus the height of the flow.")
	assert.Equal(t, 480.0, cs.positionNextCell.X, "The X position of the next cell should be updated to the x of the target plus the offset.")
	assert.Equal(t, 500.0, cs.positionNextCell.Y, "The Y position of the next cell should remain unchanged.")
	assert.Equal(t, 100.0, cs.maxHeightCurrentRow, "The maximum height of the current row should be updated to the height of the flow.")
}

// TestPositionCellWithExceedingMapWidth tests the PositionCell function by checking if it correctly wraps to the next row
// when the cell exceeds the map width, adjusting the next cell's position and the maximum height of the current row.
func TestPositionCellWithExceedingMapWidth(t *testing.T) {
	cs := &CoordinateSystem{
		width:               1000.0,
		offsetNextCell:      50.0,
		maxHeightCurrentRow: 80.0,
		positionNextCell:    VertexClass{X: 950.0, Y: 500.0},
		logger:              slog.Default(),
	}

	// Position the process cell
	process := &Cell{
		Data: Data{
			Type: "tm.Process",
		},
		Position: &VertexClass{X: 0.0, Y: 0.0},
		Size:     &Size{Width: 60.0, Height: 60.0}, // Width exceeds the map width
	}

	// Position the cell
	PositionCell(cs, process)

	assert.Equal(t, 0.0, process.Position.X, "The X position of the cell should be wrapped to the next row.")
	assert.Equal(t, 630.0, process.Position.Y, "The Y position of the cell should be wrapped to the next row.")
	assert.Equal(t, 110.0, cs.positionNextCell.X, "The X position of the next cell should be updated to the width of the cell plus the offset.")
	assert.Equal(t, 630.0, cs.positionNextCell.Y, "The Y position of the next cell should be wrapped to the next row.")
	assert.Equal(t, 60.0, cs.maxHeightCurrentRow, "The maximum height of the current row should be updated to the height of the cell.")

	flow := &Cell{
		Data: Data{
			Type: "tm.Flow",
		},
		Width:  float64Ptr(900.0),
		Height: float64Ptr(100.0),
		Source: &Source{X: int64Ptr(0), Y: int64Ptr(0)},
		Target: &Source{X: int64Ptr(0), Y: int64Ptr(0)},
	}

	// Position the flow cell
	PositionCell(cs, flow)

	assert.Equal(t, 0, int(*flow.Source.X), "The X position of the flow source should be wrapped to the next row.")
	assert.Equal(t, 740, int(*flow.Source.Y), "The Y position of the flow source should be wrapped to the next row.")
	assert.Equal(t, 900, int(*flow.Target.X), "The X position of the flow target should be the source position plus the width of the flow.")
	assert.Equal(t, 840, int(*flow.Target.Y), "The Y position of the flow target should be the source position plus the height of the flow.")
	assert.Equal(t, 950.0, cs.positionNextCell.X, "The X position of the next cell should be updated to the x of the target plus the offset.")
	assert.Equal(t, 740.0, cs.positionNextCell.Y, "The Y position of the next cell should be wrapped to the next row.")
	assert.Equal(t, 100.0, cs.maxHeightCurrentRow, "The maximum height of the current row should be updated to the height of the flow.")
}

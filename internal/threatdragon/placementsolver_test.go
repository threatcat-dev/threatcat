package threatdragon

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

var TestConfig = DefaultSolverConfig()

func boxes(ids ...string) []BoxDef {
	res := make([]BoxDef, len(ids))
	for i, id := range ids {
		res[i] = BoxDef{ID: id}
	}
	return res
}

func nodes(ids ...string) []NodeDef {
	res := make([]NodeDef, len(ids))
	for i, id := range ids {
		res[i] = NodeDef{ID: id}
	}
	return res
}

func TestSolve(t *testing.T) {
	tests := []struct {
		name        string
		boxDefs     []BoxDef
		nodeDefs    []NodeDef
		memberships []Membership
		wantErr     bool
		expectBoxes int
		expectNodes int
	}{
		{
			name:        "No boxes or nodes",
			boxDefs:     nil,
			nodeDefs:    nil,
			memberships: nil,
			wantErr:     false,
		},
		{
			name:        "One node, no boxes",
			boxDefs:     nil,
			nodeDefs:    nodes("n1"),
			memberships: nil,
			wantErr:     false,
			expectNodes: 1,
		},
		{
			name:        "One box, no nodes",
			boxDefs:     boxes("A"),
			nodeDefs:    nil,
			memberships: nil,
			wantErr:     false,
			expectBoxes: 1,
		},
		{
			name:     "One box, one node inside",
			boxDefs:  boxes("A"),
			nodeDefs: nodes("n1"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
			},
			wantErr:     false,
			expectBoxes: 1,
			expectNodes: 1,
		},
		{
			name:        "One box, one node outside",
			boxDefs:     boxes("A"),
			nodeDefs:    nodes("n1"),
			memberships: []Membership{},
			wantErr:     false,
			expectBoxes: 1,
			expectNodes: 1,
		},
		{
			name:     "One box, two nodes inside",
			boxDefs:  boxes("A"),
			nodeDefs: nodes("n1", "n2"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n2", BoxID: "A"},
			},
			wantErr:     false,
			expectBoxes: 1,
			expectNodes: 2,
		},
		{
			name:     "One box, one node inside, one outside",
			boxDefs:  boxes("A"),
			nodeDefs: nodes("n1", "n2"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
			},
			wantErr:     false,
			expectBoxes: 1,
			expectNodes: 2,
		},
		{
			name:     "Two boxes, one node inside both (boxes must overlap)",
			boxDefs:  boxes("A", "B"),
			nodeDefs: nodes("n1"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "B"},
			},
			wantErr:     false,
			expectBoxes: 2,
			expectNodes: 1,
		},
		{
			name:     "Two boxes, one node only in A",
			boxDefs:  boxes("A", "B"),
			nodeDefs: nodes("n1"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
			},
			wantErr:     false,
			expectBoxes: 2,
			expectNodes: 1,
		},
		{
			name:     "Two boxes, node in A only and another in B only",
			boxDefs:  boxes("A", "B"),
			nodeDefs: nodes("n1", "n2"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n2", BoxID: "B"},
			},
			wantErr:     false,
			expectBoxes: 2,
			expectNodes: 2,
		},
		{
			name:     "Two boxes, node in both and another outside both",
			boxDefs:  boxes("A", "B"),
			nodeDefs: nodes("n1", "n2"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "B"},
			},
			wantErr:     false,
			expectBoxes: 2,
			expectNodes: 2,
		},
		{
			name:     "Three boxes, three nodes, distinct membership patterns",
			boxDefs:  boxes("A", "B", "C"),
			nodeDefs: nodes("n1", "n2", "n3"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "B"},
				{NodeID: "n2", BoxID: "B"},
				{NodeID: "n2", BoxID: "C"},
				{NodeID: "n3", BoxID: "A"},
				{NodeID: "n3", BoxID: "C"},
			},
			wantErr:     false,
			expectBoxes: 3,
			expectNodes: 3,
		},
		{
			name:     "Four overlapping boxes, solvable",
			boxDefs:  boxes("A", "B", "C", "D"),
			nodeDefs: nodes("n1", "n2", "n3", "n4"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "B"},
				{NodeID: "n2", BoxID: "B"},
				{NodeID: "n2", BoxID: "C"},
				{NodeID: "n3", BoxID: "C"},
				{NodeID: "n3", BoxID: "D"},
				{NodeID: "n4", BoxID: "A"},
				{NodeID: "n4", BoxID: "D"},
			},
			wantErr:     false,
			expectBoxes: 4,
			expectNodes: 4,
		},
		{
			name:     "Four overlapping boxes, difficult solvable",
			boxDefs:  boxes("A", "B", "C", "D"),
			nodeDefs: nodes("n1", "n2", "n3", "n4"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "C"},
				{NodeID: "n1", BoxID: "D"},
				{NodeID: "n2", BoxID: "B"},
				{NodeID: "n2", BoxID: "C"},
				{NodeID: "n3", BoxID: "C"},
				{NodeID: "n3", BoxID: "D"},
				{NodeID: "n4", BoxID: "A"},
				{NodeID: "n4", BoxID: "D"},
			},
			wantErr:     false,
			expectBoxes: 4,
			expectNodes: 4,
		},
		{
			name:     "Three boxes, node inside all, node in none, node in subset",
			boxDefs:  boxes("A", "B", "C"),
			nodeDefs: nodes("n1", "n2", "n3"),
			memberships: []Membership{
				{NodeID: "n1", BoxID: "A"},
				{NodeID: "n1", BoxID: "B"},
				{NodeID: "n1", BoxID: "C"},
				{NodeID: "n3", BoxID: "A"},
			},
			wantErr:     false,
			expectBoxes: 3,
			expectNodes: 3,
		},
		{
			name:        "Empty memberships but boxes and nodes exist",
			boxDefs:     boxes("A", "B"),
			nodeDefs:    nodes("n1", "n2"),
			memberships: nil,
			wantErr:     false,
			expectBoxes: 2,
			expectNodes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Solve(tt.boxDefs, tt.nodeDefs, tt.memberships, TestConfig, SolveOptions{})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Sanity: number of results should match expectations
				assert.Len(t, got.Boxes, tt.expectBoxes)
				assert.Len(t, got.Nodes, tt.expectNodes)

				// All placed entities must be within grid bounds (pixel coordinates)
				for _, b := range got.Boxes {
					if b.X < 0 || b.Y < 0 || b.X+b.W > TestConfig.GridW*int(TestConfig.GridSizeX) || b.Y+b.H > TestConfig.GridH*int(TestConfig.GridSizeX) {
						t.Errorf("box %s out of bounds: %+v", b.ID, b)
					}
				}
				for _, n := range got.Nodes {
					if n.X < 0 || n.Y < 0 || n.X >= TestConfig.GridW*int(TestConfig.GridSizeX) || n.Y >= TestConfig.GridH*int(TestConfig.GridSizeY) {
						t.Errorf("node %s out of bounds: %+v", n.ID, n)
					}
				}
			}
		})
	}
}

func TestSolve_FourNodesEquallySpaced(t *testing.T) {
	sol, err := Solve(
		boxes("B"),
		nodes("n1", "n2", "n3", "n4"),
		[]Membership{
			{NodeID: "n1", BoxID: "B"},
			{NodeID: "n2", BoxID: "B"},
			{NodeID: "n3", BoxID: "B"},
			{NodeID: "n4", BoxID: "B"},
		},
		TestConfig,
		SolveOptions{},
	)
	assert.NoError(t, err)
	assert.Len(t, sol.Boxes, 1)
	assert.Len(t, sol.Nodes, 4)

	// Get boundary position via the public method.
	bx, by, bw, bh, err := sol.GetBoundaryPosition("B")
	assert.NoError(t, err, "Expected no error for boundary 'B'")
	t.Logf("Boundary B: x=%.0f y=%.0f w=%.0f h=%.0f", bx, by, bw, bh)

	// Get node positions via the public method.
	nodeIDs := []string{"n1", "n2", "n3", "n4"}
	xSet := map[float64]bool{}
	ySet := map[float64]bool{}
	for _, id := range nodeIDs {
		nx, ny, err := sol.GetPosition(id, TestConfig.NodeAssumedHeight, TestConfig.NodeAssumedWidth)
		assert.NoError(t, err, "Expected no error for asset %s", id)
		t.Logf("Node %s: x=%.0f y=%.0f", id, nx, ny)
		xSet[nx] = true
		ySet[ny] = true
	}

	// 4 nodes should form a 2×2 grid.
	assert.Len(t, xSet, 2, "expected 2 distinct X positions")
	assert.Len(t, ySet, 2, "expected 2 distinct Y positions")

	var xs, ys []float64
	for x := range xSet {
		xs = append(xs, x)
	}
	for y := range ySet {
		ys = append(ys, y)
	}
	sort.Float64s(xs)
	sort.Float64s(ys)

	// Node centres should be evenly distributed: margin from boundary edge
	// to node centre = half the gap between node centres.
	nodeCenterX0 := xs[0] + TestConfig.NodeAssumedWidth/2
	nodeCenterX1 := xs[1] + TestConfig.NodeAssumedWidth/2
	xGap := nodeCenterX1 - nodeCenterX0
	leftMargin := nodeCenterX0 - bx
	rightMargin := (bx + bw) - nodeCenterX1
	t.Logf("Visual horizontal: leftMargin=%.1f xGap=%.1f rightMargin=%.1f", leftMargin, xGap, rightMargin)
	assert.Equal(t, leftMargin, rightMargin, "left margin should equal right margin")
	assert.Equal(t, leftMargin, xGap/2, "margin should be half the gap")

	nodeCenterY0 := ys[0] + TestConfig.NodeAssumedHeight/2
	nodeCenterY1 := ys[1] + TestConfig.NodeAssumedHeight/2
	yGap := nodeCenterY1 - nodeCenterY0
	topMargin := nodeCenterY0 - by
	bottomMargin := (by + bh) - nodeCenterY1
	t.Logf("Visual vertical: topMargin=%.1f yGap=%.1f bottomMargin=%.1f", topMargin, yGap, bottomMargin)
	assert.Equal(t, topMargin, bottomMargin, "top margin should equal bottom margin")
	assert.Equal(t, topMargin, yGap/2, "margin should be half the gap")
}

func TestSolve_SixNodesOverlapAndRowScaling(t *testing.T) {
	// With AllowNodeOverlap: true, 6 nodes can share a single box even when the
	// solver picks the minimum 2×2 box (4 cells). The greedy assignment stacks
	// two pairs of nodes in the same cells, which must produce SubOffset > 0 for
	// the extras and force GetBoundaryPosition to expand the boundary height.
	sol, err := Solve(
		boxes("B"),
		nodes("n1", "n2", "n3", "n4", "n5", "n6"),
		[]Membership{
			{NodeID: "n1", BoxID: "B"},
			{NodeID: "n2", BoxID: "B"},
			{NodeID: "n3", BoxID: "B"},
			{NodeID: "n4", BoxID: "B"},
			{NodeID: "n5", BoxID: "B"},
			{NodeID: "n6", BoxID: "B"},
		},
		TestConfig,
		SolveOptions{AllowNodeOverlap: true},
	)
	assert.NoError(t, err)
	assert.Len(t, sol.Boxes, 1)
	assert.Len(t, sol.Nodes, 6)

	// Capture the base box height before CalculateRowHeights mutates it.
	baseH := float64(sol.Boxes[0].H)

	// CalculateRowHeights assigns SubOffset values to stacked nodes.
	sol.CalculateRowHeights()

	maxSubOffset := 0
	for _, n := range sol.Nodes {
		if n.SubOffset > maxSubOffset {
			maxSubOffset = n.SubOffset
		}
	}
	assert.Greater(t, maxSubOffset, 0, "at least one node should be stacked (SubOffset > 0)")

	// GetBoundaryPosition must return an expanded height to accommodate stacked nodes.
	bx, by, bw, bh, err := sol.GetBoundaryPosition("B")
	assert.NoError(t, err, "Expected no error for boundary 'B'")
	t.Logf("Boundary B: x=%.0f y=%.0f w=%.0f h=%.0f", bx, by, bw, bh)

	assert.Greater(t, bh, baseH, "boundary height should be expanded to accommodate stacked nodes")

	// Every node, including its stacked offset, must lie within the expanded boundary,
	// and each node must occupy a unique rendered position.
	type pos struct{ x, y float64 }
	positions := map[pos]string{}
	for _, n := range sol.Nodes {
		nx, ny, err := sol.GetPosition(n.ID, TestConfig.NodeAssumedHeight, TestConfig.NodeAssumedWidth)
		assert.NoError(t, err, "Expected no error for asset %s", n.ID)
		t.Logf("Node %s: x=%.0f y=%.0f (subOffset=%d)", n.ID, nx, ny, n.SubOffset)
		assert.GreaterOrEqual(t, nx, bx, "node %s left edge should be inside boundary", n.ID)
		assert.LessOrEqual(t, nx+TestConfig.NodeAssumedWidth, bx+bw, "node %s right edge should be inside boundary", n.ID)
		assert.GreaterOrEqual(t, ny, by, "node %s top edge should be inside boundary", n.ID)
		assert.LessOrEqual(t, ny+TestConfig.NodeAssumedHeight, by+bh, "node %s bottom edge should be inside boundary", n.ID)
		p := pos{nx, ny}
		if other, seen := positions[p]; seen {
			t.Errorf("node %s has the same rendered position as node %s (x=%.0f y=%.0f)", n.ID, other, nx, ny)
		}
		positions[p] = n.ID
	}
}

func TestSolve_FreeNodeFillsOpenSlot(t *testing.T) {
	// Box B is fixed at pixel origin (0,0), 2×2 grid cells (400×400 px).
	// The four cell centres inside it are labelled by (col, row) in grid units:
	//   slot 0: col=0 row=0 → (100,100)
	//   slot 1: col=1 row=0 → (300,100)
	//   slot 2: col=0 row=1 → (100,300)
	//   slot 3: col=1 row=1 → (300,300)
	// In each case one node is left free; it must land in the remaining slot.
	cellX := func(col int) int { return (2*col + 1) * int(TestConfig.GridSizeX) / 2 }
	cellY := func(row int) int { return (2*row + 1) * int(TestConfig.GridSizeY) / 2 }

	slots := [4][2]int{{0, 0}, {1, 0}, {0, 1}, {1, 1}}

	tests := []struct {
		freeNode string
		wantSlot int // index into slots[] where the free node must land
	}{
		{freeNode: "n1", wantSlot: 0},
		{freeNode: "n2", wantSlot: 1},
		{freeNode: "n3", wantSlot: 2},
		{freeNode: "n4", wantSlot: 3},
	}

	for _, tt := range tests {
		t.Run("free="+tt.freeNode, func(t *testing.T) {
			nodeDefs := make([]NodeDef, 4)
			for i, id := range []string{"n1", "n2", "n3", "n4"} {
				if id == tt.freeNode {
					nodeDefs[i] = NodeDef{ID: id}
				} else {
					nodeDefs[i] = NodeDef{
						ID:    id,
						Fixed: true,
						X:     cellX(slots[i][0]),
						Y:     cellY(slots[i][1]),
					}
				}
			}

			sol, err := Solve(
				[]BoxDef{{ID: "B", Fixed: true, X: 0, Y: 0, W: 2 * int(TestConfig.GridSizeX), H: 2 * int(TestConfig.GridSizeY)}},
				nodeDefs,
				[]Membership{
					{NodeID: "n1", BoxID: "B"},
					{NodeID: "n2", BoxID: "B"},
					{NodeID: "n3", BoxID: "B"},
					{NodeID: "n4", BoxID: "B"},
				},
				TestConfig,
				SolveOptions{},
			)
			assert.NoError(t, err)
			assert.Len(t, sol.Boxes, 1)
			assert.Len(t, sol.Nodes, 4)

			var free PlacedNode
			for _, n := range sol.Nodes {
				if n.ID == tt.freeNode {
					free = n
					break
				}
			}
			wantX := cellX(slots[tt.wantSlot][0])
			wantY := cellY(slots[tt.wantSlot][1])
			assert.Equal(t, wantX, free.X, "free node should fill the open column")
			assert.Equal(t, wantY, free.Y, "free node should fill the open row")
		})
	}
}

func TestSolve_FourNodesEquallySpacedRaw(t *testing.T) {
	sol, err := Solve(
		boxes("B"),
		nodes("n1", "n2", "n3", "n4"),
		[]Membership{
			{NodeID: "n1", BoxID: "B"},
			{NodeID: "n2", BoxID: "B"},
			{NodeID: "n3", BoxID: "B"},
			{NodeID: "n4", BoxID: "B"},
		},
		TestConfig,
		SolveOptions{},
	)
	assert.NoError(t, err)
	assert.Len(t, sol.Boxes, 1)
	assert.Len(t, sol.Nodes, 4)

	box := sol.Boxes[0]
	t.Logf("Raw box: X=%d Y=%d W=%d H=%d", box.X, box.Y, box.W, box.H)

	rawXSet := map[int]bool{}
	rawYSet := map[int]bool{}
	for _, n := range sol.Nodes {
		t.Logf("Raw node %s: X=%d Y=%d", n.ID, n.X, n.Y)
		rawXSet[n.X] = true
		rawYSet[n.Y] = true
	}

	assert.Len(t, rawXSet, 2, "expected 2 distinct raw X positions")
	assert.Len(t, rawYSet, 2, "expected 2 distinct raw Y positions")

	var rawXs, rawYs []int
	for x := range rawXSet {
		rawXs = append(rawXs, x)
	}
	for y := range rawYSet {
		rawYs = append(rawYs, y)
	}
	sort.Ints(rawXs)
	sort.Ints(rawYs)

	// Nodes are centred in their grid cells. The margin from boundary edge
	// to node centre should be half the gap between node centres.
	rawLeftMargin := rawXs[0] - box.X
	rawXGap := rawXs[1] - rawXs[0]
	rawRightMargin := (box.X + box.W) - rawXs[1]
	t.Logf("Raw horizontal: leftMargin=%d xGap=%d rightMargin=%d", rawLeftMargin, rawXGap, rawRightMargin)
	assert.Equal(t, rawLeftMargin, rawRightMargin, "raw left margin should equal right margin")
	assert.Equal(t, rawLeftMargin, rawXGap/2, "raw margin should be half the gap")

	rawTopMargin := rawYs[0] - box.Y
	rawYGap := rawYs[1] - rawYs[0]
	rawBottomMargin := (box.Y + box.H) - rawYs[1]
	t.Logf("Raw vertical: topMargin=%d yGap=%d bottomMargin=%d", rawTopMargin, rawYGap, rawBottomMargin)
	assert.Equal(t, rawTopMargin, rawBottomMargin, "raw top margin should equal bottom margin")
	assert.Equal(t, rawTopMargin, rawYGap/2, "raw margin should be half the gap")
}

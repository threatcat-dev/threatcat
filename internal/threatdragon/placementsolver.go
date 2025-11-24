package threatdragon

import (
	"fmt"
	"slices"

	"github.com/threatcat-dev/threatcat/internal/common"
)

const (
	GRID_W = 10 // grid width (x from 0..GRID_W-1)
	GRID_H = 10 // grid height (y from 0..GRID_H-1)

	MIN_BOX_W = 2
	MAX_BOX_W = 4
	MIN_BOX_H = 2
	MAX_BOX_H = 4

	solutionOffsetX          = 200.0
	solutionOffsetY          = 100.0
	solutionBoundaryOversize = 10.0
)

// Input types
type Membership struct {
	NodeID string
	BoxID  string
}

type BoxDef struct {
	ID string
}
type NodeDef struct {
	ID string
}

// Solution types
type PlacedBox struct {
	ID string
	X  int
	Y  int
	W  int
	H  int
}
type PlacedNode struct {
	ID        string
	X         int
	Y         int
	SubOffset int
}

type Solution struct {
	Boxes      []PlacedBox
	Nodes      []PlacedNode
	RowHeights []int
}

func (s *Solution) CalculateRowHeights() {
	nodeCount := make([][]int, GRID_H)
	for i := range GRID_H {
		nodeCount[i] = make([]int, GRID_W)
	}

	for i, node := range s.Nodes {
		s.Nodes[i].SubOffset = nodeCount[node.Y][node.X]
		nodeCount[node.Y][node.X]++
	}

	s.RowHeights = make([]int, GRID_H)
	for i, nodeCountCols := range nodeCount {
		s.RowHeights[i] = slices.Max(nodeCountCols)
	}
}

func (s *Solution) GetPosition(assetID string) (float64, float64) {
	if s.RowHeights == nil {
		s.CalculateRowHeights()
	}

	var foundNode PlacedNode
	for _, node := range s.Nodes {
		if node.ID == assetID {
			foundNode = node
			break
		}
	}
	if foundNode.ID == "" {
		panic("asset does not exist in solution")
	}

	x := float64(foundNode.X) * solutionOffsetX

	sumRowHeight := 0
	for _, rowHeight := range s.RowHeights[:foundNode.Y] {
		sumRowHeight += rowHeight
	}
	y := float64(sumRowHeight+foundNode.SubOffset) * solutionOffsetY

	return x + 50, y + 50
}

func (s *Solution) GetBoundaryPosition(boundaryID string) (float64, float64, float64, float64) {
	if s.RowHeights == nil {
		s.CalculateRowHeights()
	}

	var foundBox PlacedBox
	for _, box := range s.Boxes {
		if box.ID == boundaryID {
			foundBox = box
			break
		}
	}
	if foundBox.ID == "" {
		panic("boundary does not exist in solution")
	}

	x := float64(foundBox.X)*solutionOffsetX - solutionBoundaryOversize
	w := float64(foundBox.W)*solutionOffsetX + 2*solutionBoundaryOversize

	sumRowHeight1 := 0
	for _, rowHeight := range s.RowHeights[:foundBox.Y] {
		sumRowHeight1 += rowHeight
	}

	y := float64(sumRowHeight1)*solutionOffsetY - solutionBoundaryOversize

	sumRowHeight2 := sumRowHeight1
	for _, rowHeight := range s.RowHeights[foundBox.Y : foundBox.Y+foundBox.H] {
		sumRowHeight2 += rowHeight
	}

	h := float64(sumRowHeight2)*solutionOffsetY + 2*solutionBoundaryOversize

	return x + 50, y + 50, w, h
}

// Helper: membership lookup maps
func buildLookup(memberships []Membership) map[string]map[string]bool {
	nodeToBoxes := map[string]map[string]bool{}
	for _, m := range memberships {
		if _, ok := nodeToBoxes[m.NodeID]; !ok {
			nodeToBoxes[m.NodeID] = map[string]bool{}
		}
		nodeToBoxes[m.NodeID][m.BoxID] = true
	}
	return nodeToBoxes
}

// Check whether a point (px,py) is inside a given placed box
func pointInBox(px, py int, b PlacedBox) bool {
	return px >= b.X && px < b.X+b.W && py >= b.Y && py < b.Y+b.H
}

// Given the set of placed boxes, build for each node the set of possible grid cells
// that satisfy constraints *with regard to the placed boxes only*.
// For boxes not yet placed we can't enforce membership yet, so those are ignored here.
// The returned map: nodeID -> list of (x,y) encoded as x*GRID_H+y
func possibleCellsForNodes(placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, placedBoxIDs map[string]PlacedBox) map[string][]int {
	res := map[string][]int{}

	// For each grid cell compute which placed boxes it falls into
	cellInside := make([]map[string]bool, GRID_W*GRID_H)
	for x := range GRID_W {
		for y := range GRID_H {
			idx := x*GRID_H + y
			cellInside[idx] = map[string]bool{}
			for _, b := range placed {
				if pointInBox(x, y, b) {
					cellInside[idx][b.ID] = true
				}
			}
		}
	}

	for _, n := range nodes {
		wantBoxes := nodeToBoxes[n.ID] // may be nil => wants no boxes
		cands := []int{}
		for x := range GRID_W {
			for y := range GRID_H {
				idx := x*GRID_H + y
				ok := true
				// For each box that is placed, ensure membership matches the 'want' for this node
				for pid := range placedBoxIDs {
					inside := cellInside[idx][pid]
					want := wantBoxes[pid] // false if nil
					if inside && !want {
						ok = false
						break
					}
					if !inside && want {
						ok = false
						break
					}
				}
				if ok {
					cands = append(cands, idx)
				}
			}
		}
		res[n.ID] = cands
	}
	return res
}

// When all boxes are placed, compute final allowed cells for nodes considering all boxes.
func finalPossibleCells(placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool) map[string][]int {
	res := map[string][]int{}
	for x := range GRID_W {
		for y := range GRID_H {
			idx := x*GRID_H + y
			for _, n := range nodes {
				ok := true
				for _, b := range placed {
					inside := pointInBox(x, y, b)
					want := nodeToBoxes[n.ID][b.ID]
					if inside && !want {
						ok = false
						break
					}
					if !inside && want {
						ok = false
						break
					}
				}
				if ok {
					res[n.ID] = append(res[n.ID], idx)
				}
			}
		}
	}
	return res
}

// Deterministic backtracking to place boxes
func placeBoxesRecursive(boxDefs []BoxDef, idx int, placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, boxIndexMap map[string]int) ([]PlacedBox, bool) {
	if idx >= len(boxDefs) {
		// all boxes placed
		return placed, true
	}

	x0Placed, y0Placed := false, false
	for _, pb := range placed {
		if pb.X == 0 {
			x0Placed = true
		}
		if pb.Y == 0 {
			y0Placed = true
		}

		if x0Placed && y0Placed {
			break
		}
	}

	bdef := boxDefs[idx]
	// Iterate deterministically over x,y,w,h
	for w := MIN_BOX_W; w <= MAX_BOX_W; w++ {
		for h := MIN_BOX_H; h <= MAX_BOX_H; h++ {
			for x := 0; x <= GRID_W-w; x++ {
				// Prune: at least one box needs to start on x0 and y0 respectively.
				// Otherwise its just another solution shifted around.
				if !x0Placed && x > 0 {
					break
				}
				for y := 0; y <= GRID_H-h; y++ {
					if !y0Placed && y > 0 {
						break
					}

					b := PlacedBox{ID: bdef.ID, X: x, Y: y, W: w, H: h}
					placed2 := append(placed, b)
					// Build map of placed box IDs for fast lookups
					placedBoxIDs := map[string]PlacedBox{}
					for _, pb := range placed2 {
						placedBoxIDs[pb.ID] = pb
					}

					// Prune: for each node there must be at least one cell that still can satisfy
					// the constraints with regard to the placed boxes so far.
					possible := possibleCellsForNodes(placed2, nodes, nodeToBoxes, placedBoxIDs)
					ok := true
					for _, n := range nodes {
						if len(possible[n.ID]) == 0 {
							ok = false
							break
						}
					}
					if !ok {
						continue // try next box placement
					}
					// Recurse
					if solution, found := placeBoxesRecursive(boxDefs, idx+1, placed2, nodes, nodeToBoxes, boxIndexMap); found {
						return solution, true
					}
				}
			}
		}
	}
	// no placement worked for this box
	return nil, false
}

// Once boxes are placed, assign nodes to cells
func assignNodes(nodes []NodeDef, allowed map[string][]int) (map[string]int, bool) {
	assign := map[string]int{}
	// Deterministic order of nodes: by ID (stable)
	// To keep deterministic without sorting (IDs may be arbitrary), we'll use the order in nodes slice.
	var backtrack func(i int) bool
	backtrack = func(i int) bool {
		if i >= len(nodes) {
			return true
		}
		n := nodes[i]
		cands := allowed[n.ID]
		// Deterministic: iterate in ascending index
		for _, cell := range cands {
			// pick
			assign[n.ID] = cell
			if backtrack(i + 1) {
				return true
			}
			// undo
			delete(assign, n.ID)
		}
		return false
	}
	if backtrack(0) {
		return assign, true
	}
	return nil, false
}

func encodeXY(idx int) (int, int) {
	return idx / GRID_H, idx % GRID_H
}

func Solve(boxDefs []BoxDef, nodes []NodeDef, memberships []Membership) (Solution, error) {
	nodeToBoxes := buildLookup(memberships)

	// map box id to index (ordering)
	boxIndexMap := map[string]int{}
	for i, b := range boxDefs {
		boxIndexMap[b.ID] = i
	}

	// Place boxes deterministically using backtracking with pruning
	placedBoxes, ok := placeBoxesRecursive(boxDefs, 0, []PlacedBox{}, nodes, nodeToBoxes, boxIndexMap)
	if !ok {
		return Solution{}, fmt.Errorf("no arrangement of boxes and nodes found on a %dx%d grid with the chosen sizes", GRID_W, GRID_H)
	}

	// For the final placed boxes compute allowed cells for each node
	allowed := finalPossibleCells(placedBoxes, nodes, nodeToBoxes)

	// Quick fail if any node has zero allowed cells
	for _, n := range nodes {
		if len(allowed[n.ID]) == 0 {
			return Solution{}, fmt.Errorf("no allowed position for node %s after boxes placed", n.ID)
		}
	}

	// Assign nodes to cells deterministically
	assign, ok := assignNodes(nodes, allowed)
	if !ok {
		return Solution{}, fmt.Errorf("couldn't assign nodes to distinct cells (try allowNodeOverlap=true or expand grid)")
	}

	placedNodes := []PlacedNode{}
	for _, n := range nodes {
		idx := assign[n.ID]
		x, y := encodeXY(idx)
		placedNodes = append(placedNodes, PlacedNode{ID: n.ID, X: x, Y: y})
	}

	return Solution{Boxes: placedBoxes, Nodes: placedNodes}, nil
}

func SolveModel(assets []common.Asset, boundaries []common.TrustBoundary) (Solution, error) {
	nodeDefs := make([]NodeDef, 0, len(assets))
	for _, asset := range assets {
		nodeDefs = append(nodeDefs, NodeDef{
			ID: asset.ID,
		})
	}

	boxDefs := make([]BoxDef, 0, len(boundaries))
	memberships := make([]Membership, 0, len(assets)) // len(assets) is only an estimate. The slice will scale if necessary
	for _, boundary := range boundaries {
		boxDefs = append(boxDefs, BoxDef{
			ID: boundary.ID,
		})
		for _, containedAssetID := range boundary.ContainedAssets {
			memberships = append(memberships, Membership{
				BoxID:  boundary.ID,
				NodeID: containedAssetID,
			})
		}
	}

	return Solve(boxDefs, nodeDefs, memberships)
}

// This file implements the constraint-based backtracking placement solver for trust boundaries and assets.

package threatdragon

import (
	"fmt"
	"math"
	"sort"

	"github.com/threatcat-dev/threatcat/internal/common"
)

// SolverConfig holds the configuration for the placement solver.
type SolverConfig struct {
	GridW int // grid width (x from 0..gridW-1)
	GridH int // grid height (y from 0..gridH-1)

	MinBoxW int
	MaxBoxW int
	MinBoxH int
	MaxBoxH int

	// static offsets to be applied to all elements when getting positions for threatdragon
	GlobalOffsetX float64
	GlobalOffsetY float64

	// Pixel delta between adjacent grid cells.
	// All PlacedBox and PlacedNode coordinates are multiples of these values.
	GridSizeX float64
	GridSizeY float64

	// NodeAssumedWidth and NodeAssumedHeight are the dimensions used to centre a node
	// within its grid cell and to expand boundary rectangles for stacked nodes.
	// Must match defaultProcessWidth / defaultProcessHeight in output.go (stores have the
	// same height but a wider width; they end up slightly right of centre, which is fine).
	NodeAssumedWidth  float64
	NodeAssumedHeight float64
}

// SolveOptions controls placement behaviour.
type SolveOptions struct {
	// AllowNodeOverlap permits multiple nodes to share the same grid cell.
	// When true, boundary heights are expanded at render time to accommodate
	// stacked nodes. This is the original behaviour and scales to any number
	// of assets per membership combination.
	// When false (default for updates), every node is assigned a unique cell;
	// the solver returns an error when there are more nodes than available cells.
	AllowNodeOverlap bool
}

// Input types

type Membership struct {
	NodeID string
	BoxID  string
}

type BoxDef struct {
	ID    string
	Fixed bool
	X     int // pixel coordinate (multiple of gridSizeX)
	Y     int // pixel coordinate (multiple of gridSizeY)
	W     int // pixel width (multiple of gridSizeX)
	H     int // pixel height (multiple of gridSizeY)
}

type NodeDef struct {
	ID    string
	Fixed bool
	X     int // pixel coordinate, snapped to nearest grid cell (if Fixed)
	Y     int // pixel coordinate, snapped to nearest grid cell (if Fixed)
}

// Solution types

type PlacedBox struct {
	ID string
	X  int // pixel coordinate
	Y  int // pixel coordinate
	W  int // pixel width
	H  int // pixel height
}

type PlacedNode struct {
	ID        string
	X         int // pixel coordinate
	Y         int // pixel coordinate
	SubOffset int // stacking index when multiple nodes share a grid cell
}

type Solution struct {
	Boxes                []PlacedBox
	Nodes                []PlacedNode
	rowHeightsCalculated bool
	memberships          []Membership
	config               SolverConfig
}

// DefaultSolverConfig returns a SolverConfig with sensible defaults for a 10x10 grid.
func DefaultSolverConfig() SolverConfig {
	return SolverConfig{
		GridW:             10,
		GridH:             10,
		MinBoxW:           2,
		MaxBoxW:           4,
		MinBoxH:           2,
		MaxBoxH:           4,
		GlobalOffsetX:     50,
		GlobalOffsetY:     50,
		GridSizeX:         200,
		GridSizeY:         200,
		NodeAssumedWidth:  60,
		NodeAssumedHeight: 60,
	}
}

// CalculateRowHeights assigns SubOffset values to nodes that share the same pixel
// grid cell, then mutates PlacedNode.Y and PlacedBox coordinates so that the
// stored values are final display positions with no further adjustment needed.
//
// It processes rows top-to-bottom. For each row that has stacked nodes (max
// SubOffset > 0), it shifts everything below that row downward by the required
// number of grid rows, expands any box that spans the row boundary, and bakes
// each stacked node's SubOffset into its Y coordinate.
//
// After this call, GetPosition and GetBoundaryPosition use the stored coordinates
// directly — no SubOffset arithmetic is needed at query time.
func (s *Solution) CalculateRowHeights() {
	// Step 1: assign per-cell SubOffset (stacking index within each shared cell).
	nodeCount := make(map[[2]int]int)
	for i, node := range s.Nodes {
		key := [2]int{node.X, node.Y}
		s.Nodes[i].SubOffset = nodeCount[key]
		nodeCount[key]++
	}

	// Step 2: snapshot each node's original row (Y value) before any mutation,
	// and compute the max SubOffset per row. Both must be done before the loop
	// so that baked positions from earlier rows don't confuse later ones.
	originalRow := make([]int, len(s.Nodes))
	maxSOInRow := make(map[int]int)
	for i, node := range s.Nodes {
		originalRow[i] = node.Y
		if node.SubOffset > maxSOInRow[node.Y] {
			maxSOInRow[node.Y] = node.SubOffset
		}
	}

	// Step 3: sort row Y values ascending.
	rows := make([]int, 0, len(maxSOInRow))
	for y := range maxSOInRow {
		rows = append(rows, y)
	}
	sort.Ints(rows)

	// Step 3b: snapshot original box positions before any mutation, analogous
	// to originalRow for nodes. Without this, the shift/expand decision for
	// boxes would mix mutated box.Y values with original rowY values, causing
	// a box that originally *spanned* a row to be incorrectly *shifted* after
	// a prior iteration inflated its Y coordinate.
	originalBoxY := make([]int, len(s.Boxes))
	originalBoxH := make([]int, len(s.Boxes))
	for i, box := range s.Boxes {
		originalBoxY[i] = box.Y
		originalBoxH[i] = box.H
	}

	// Step 4: walk rows top-to-bottom. For each row with stacked nodes, shift
	// everything below it downward, then bake SubOffset into the stacked nodes.
	// Row membership is determined by the pre-mutation originalRow snapshot so
	// that nodes baked into a new Y don't get mistaken for a different row.
	for _, rowY := range rows {
		maxSO := maxSOInRow[rowY]
		if maxSO == 0 {
			continue
		}

		shift := maxSO * int(s.config.GridSizeY)

		// Shift all nodes in lower rows.
		for i := range s.Nodes {
			if originalRow[i] > rowY {
				s.Nodes[i].Y += shift
			}
		}

		// Adjust boxes: shift those that start entirely below the row centre;
		// expand those that span across it. Use original (pre-mutation) box
		// positions so that prior shifts don't change the decision.
		for i := range s.Boxes {
			if originalBoxY[i] > rowY {
				s.Boxes[i].Y += shift
			} else if originalBoxY[i]+originalBoxH[i] > rowY {
				s.Boxes[i].H += shift
			}
		}

		// Bake stacked-node positions: fold SubOffset into Y so callers need
		// no extra arithmetic.
		for i, node := range s.Nodes {
			if originalRow[i] == rowY && node.SubOffset > 0 {
				s.Nodes[i].Y += node.SubOffset * int(s.config.GridSizeY)
			}
		}
	}

	s.rowHeightsCalculated = true
}

// GetPosition returns the pixel position (x, y) for an asset cell in the diagram.
func (s *Solution) GetPosition(assetID string, h, w float64) (float64, float64, error) {
	if !s.rowHeightsCalculated {
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
		return 0, 0, fmt.Errorf("asset %s does not exist in solution", assetID)
	}

	x := float64(foundNode.X) - w/2 + s.config.GlobalOffsetX
	y := float64(foundNode.Y) - h/2 + s.config.GlobalOffsetY
	return x, y, nil
}

// GetBoundaryPosition returns the pixel position and size (x, y, w, h) for a
// trust boundary rectangle in the diagram.
// The height is expanded when stacked nodes (SubOffset > 0) would otherwise
// exceed the base boundary rectangle.
func (s *Solution) GetBoundaryPosition(boundaryID string) (float64, float64, float64, float64, error) {
	if !s.rowHeightsCalculated {
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
		return 0, 0, 0, 0, fmt.Errorf("boundary %s does not exist in solution", boundaryID)
	}

	x := float64(foundBox.X) + s.config.GlobalOffsetX
	y := float64(foundBox.Y) + s.config.GlobalOffsetY
	w := float64(foundBox.W)
	h := float64(foundBox.H)

	// Expand h so that stacked nodes (SubOffset > 0) remain inside the boundary.
	// Mirrors GetPosition: asset bottom = node.Y + SubOffset*solutionOffsetY - nodeH/2 + globalOffsetY + nodeH.
	for _, membership := range s.memberships {
		if membership.BoxID != boundaryID {
			continue
		}
		for _, node := range s.Nodes {
			if node.ID != membership.NodeID {
				continue
			}
			assetBottom := float64(node.Y) + s.config.NodeAssumedHeight/2 + s.config.GlobalOffsetY
			if needed := assetBottom - y; needed > h {
				h = needed
			}
			break
		}
	}

	return x, y, w, h, nil
}

// Helper: build a nodeID → set-of-boxIDs lookup from the membership list.
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

// pointInBox reports whether the pixel point (px, py) lies inside a placed box.
func pointInBox(px, py int, b PlacedBox) bool {
	return px >= b.X && px < b.X+b.W && py >= b.Y && py < b.Y+b.H
}

// encodeXY converts a 1D grid index to pixel coordinates at the centre of the cell.
func encodeXY(idx int, config *SolverConfig) (int, int) {
	xi := idx / config.GridH
	yi := idx % config.GridH
	return xi*int(config.GridSizeX) + int(config.GridSizeX)/2, yi*int(config.GridSizeY) + int(config.GridSizeY)/2
}

// possibleCellsForNodes returns, for each node, the list of grid-cell indices that
// satisfy the membership constraints with respect to the boxes placed so far.
// Fixed nodes are validated at their pre-determined cell; free nodes are searched exhaustively.
func possibleCellsForNodes(placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, placedBoxIDs map[string]PlacedBox, config *SolverConfig) map[string][]int {
	res := map[string][]int{}

	// Precompute which placed boxes each grid cell centre falls inside.
	cellInside := make([]map[string]bool, config.GridW*config.GridH)
	for xi := range config.GridW {
		for yi := range config.GridH {
			idx := xi*config.GridH + yi
			x, y := encodeXY(idx, config)
			cellInside[idx] = map[string]bool{}
			for _, b := range placed {
				if pointInBox(x, y, b) {
					cellInside[idx][b.ID] = true
				}
			}
		}
	}

	for _, n := range nodes {
		wantBoxes := nodeToBoxes[n.ID]

		if n.Fixed {
			// Fixed node: only valid at its pre-assigned grid cell.
			xi := (n.X - int(config.GridSizeX)/2) / int(config.GridSizeX)
			yi := (n.Y - int(config.GridSizeY)/2) / int(config.GridSizeY)
			if xi < 0 || xi >= config.GridW || yi < 0 || yi >= config.GridH {
				res[n.ID] = []int{} // out of grid bounds → solver will fail
				continue
			}
			idx := xi*config.GridH + yi
			ok := true
			for pid := range placedBoxIDs {
				inside := cellInside[idx][pid]
				want := wantBoxes[pid]
				if inside != want {
					ok = false
					break
				}
			}
			if ok {
				res[n.ID] = []int{idx}
			} else {
				res[n.ID] = []int{}
			}
			continue
		}

		// Free node: collect all cells that satisfy membership constraints.
		cands := []int{}
		for xi := range config.GridW {
			for yi := range config.GridH {
				idx := xi*config.GridH + yi
				ok := true
				for pid := range placedBoxIDs {
					inside := cellInside[idx][pid]
					want := wantBoxes[pid]
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

// finalPossibleCells computes the allowed grid cells for each node given all placed boxes.
func finalPossibleCells(placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, config *SolverConfig) map[string][]int {
	res := map[string][]int{}

	for _, n := range nodes {
		if n.Fixed {
			// Fixed node: validate at its single pre-assigned cell.
			xi := (n.X - int(config.GridSizeX)/2) / int(config.GridSizeX)
			yi := (n.Y - int(config.GridSizeY)/2) / int(config.GridSizeY)
			if xi < 0 || xi >= config.GridW || yi < 0 || yi >= config.GridH {
				res[n.ID] = []int{}
				continue
			}
			idx := xi*config.GridH + yi
			x, y := encodeXY(idx, config)
			ok := true
			for _, b := range placed {
				inside := pointInBox(x, y, b)
				want := nodeToBoxes[n.ID][b.ID]
				if inside != want {
					ok = false
					break
				}
			}
			if ok {
				res[n.ID] = []int{idx}
			} else {
				res[n.ID] = []int{}
			}
			continue
		}

		// Free node: collect all valid cells.
		for xi := range config.GridW {
			for yi := range config.GridH {
				idx := xi*config.GridH + yi
				x, y := encodeXY(idx, config)
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

// placeBoxesRecursive uses backtracking to place boxes on the pixel grid.
// Fixed boxes are placed at their pre-determined pixel positions.
// Free boxes are tried at every valid pixel position in increments of solutionOffset*.
// When allowOverlap is false, free-box placements are also pruned when there are
// not enough distinct valid cells to give every node a unique one.
// hasElementsAtOrigin checks if at least one box starts at x=0 and one at y=0.
func hasElementsAtOrigin(placed []PlacedBox) (bool, bool) {
	x0, y0 := false, false
	for _, pb := range placed {
		if pb.X == 0 {
			x0 = true
		}
		if pb.Y == 0 {
			y0 = true
		}
		if x0 && y0 {
			break
		}
	}
	return x0, y0
}

// isPlacementValid checks if all nodes have possible cells and enough room when overlap is not allowed.
func isPlacementValid(placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, config *SolverConfig, allowOverlap bool) bool {
	placedBoxIDs := make(map[string]PlacedBox, len(placed))
	for _, pb := range placed {
		placedBoxIDs[pb.ID] = pb
	}

	possible := possibleCellsForNodes(placed, nodes, nodeToBoxes, placedBoxIDs, config)
	for _, n := range nodes {
		if len(possible[n.ID]) == 0 {
			return false
		}
	}

	// When unique-cell assignment is required, prune placements where
	// the total number of distinct valid cells across all nodes is less
	// than the number of nodes — there would never be enough room.
	if !allowOverlap {
		distinctCells := make(map[int]bool)
		for _, n := range nodes {
			for _, cell := range possible[n.ID] {
				distinctCells[cell] = true
			}
		}
		if len(distinctCells) < len(nodes) {
			return false
		}
	}

	return true
}

func placeBoxesRecursive(boxDefs []BoxDef, idx int, placed []PlacedBox, nodes []NodeDef, nodeToBoxes map[string]map[string]bool, config *SolverConfig, allowOverlap bool) ([]PlacedBox, bool) {
	if idx >= len(boxDefs) {
		return placed, true
	}

	bdef := boxDefs[idx]

	if bdef.Fixed {
		b := PlacedBox{ID: bdef.ID, X: bdef.X, Y: bdef.Y, W: bdef.W, H: bdef.H}
		placed2 := append(placed, b)
		if ok := isPlacementValid(placed2, nodes, nodeToBoxes, config, allowOverlap); ok {
			if solution, found := placeBoxesRecursive(boxDefs, idx+1, placed2, nodes, nodeToBoxes, config, allowOverlap); found {
				return solution, true
			}
		}
		return nil, false
	}

	x0Placed, y0Placed := hasElementsAtOrigin(placed)

	for wi := config.MinBoxW; wi <= config.MaxBoxW; wi++ {
		w := wi * int(config.GridSizeX)
		for hi := config.MinBoxH; hi <= config.MaxBoxH; hi++ {
			h := hi * int(config.GridSizeY)
			for xi := 0; xi <= config.GridW-wi; xi++ {
				if !x0Placed && xi > 0 {
					break
				}
				x := xi * int(config.GridSizeX)
				for yi := 0; yi <= config.GridH-hi; yi++ {
					if !y0Placed && yi > 0 {
						break
					}
					y := yi * int(config.GridSizeY)

					b := PlacedBox{ID: bdef.ID, X: x, Y: y, W: w, H: h}
					placed2 := append(placed, b)

					if ok := isPlacementValid(placed2, nodes, nodeToBoxes, config, allowOverlap); !ok {
						continue
					}

					if solution, found := placeBoxesRecursive(boxDefs, idx+1, placed2, nodes, nodeToBoxes, config, allowOverlap); found {
						return solution, true
					}
				}
			}
		}
	}
	return nil, false
}

// assignNodes assigns grid-cell indices to nodes. Fixed nodes are pre-assigned;
// free nodes are assigned according to the mode chosen by allowOverlap.
//
// When allowOverlap is true, nodes are distributed evenly across valid cells
// using a greedy least-loaded strategy: each free node is placed in the valid
// cell that currently has the fewest occupants. Fixed nodes count toward the
// load of their cells so free nodes spread away from them naturally.
//
// When allowOverlap is false, every node receives a unique cell; backtracking
// ensures a valid assignment or reports failure.
func assignNodes(nodes []NodeDef, allowed map[string][]int, config *SolverConfig, allowOverlap bool) (map[string]int, bool) {
	assign := map[string]int{}
	freeNodes := make([]NodeDef, 0, len(nodes))

	if allowOverlap {
		// Even-distribution mode: track per-cell load and greedily assign each
		// free node to the least-loaded cell among its valid candidates.
		cellLoad := map[int]int{}
		for _, n := range nodes {
			if n.Fixed {
				idx := ((n.X-int(config.GridSizeX)/2)/int(config.GridSizeX))*config.GridH + (n.Y-int(config.GridSizeY)/2)/int(config.GridSizeY)
				assign[n.ID] = idx
				cellLoad[idx]++
			} else {
				freeNodes = append(freeNodes, n)
			}
		}
		for _, n := range freeNodes {
			cands := allowed[n.ID]
			if len(cands) == 0 {
				return nil, false
			}
			best := cands[0]
			for _, cell := range cands[1:] {
				if cellLoad[cell] < cellLoad[best] {
					best = cell
				}
			}
			assign[n.ID] = best
			cellLoad[best]++
		}
		return assign, true
	}

	// Unique-cell mode: backtracking with a used-cell set.
	used := map[int]bool{}
	for _, n := range nodes {
		if n.Fixed {
			idx := ((n.X-int(config.GridSizeX)/2)/int(config.GridSizeX))*config.GridH + (n.Y-int(config.GridSizeY)/2)/int(config.GridSizeY)
			assign[n.ID] = idx
			used[idx] = true
		} else {
			freeNodes = append(freeNodes, n)
		}
	}

	var backtrack func(i int) bool
	backtrack = func(i int) bool {
		if i >= len(freeNodes) {
			return true
		}
		n := freeNodes[i]
		for _, cell := range allowed[n.ID] {
			if used[cell] {
				continue
			}
			used[cell] = true
			assign[n.ID] = cell
			if backtrack(i + 1) {
				return true
			}
			delete(assign, n.ID)
			delete(used, cell)
		}
		return false
	}
	if backtrack(0) {
		return assign, true
	}
	return nil, false
}

// Solve places boxes and assigns nodes to grid cells, returning a Solution with
// pixel coordinates for all placed elements.
func Solve(boxDefs []BoxDef, nodes []NodeDef, memberships []Membership, config SolverConfig, opts SolveOptions) (Solution, error) {
	nodeToBoxes := buildLookup(memberships)

	placedBoxes, ok := placeBoxesRecursive(boxDefs, 0, []PlacedBox{}, nodes, nodeToBoxes, &config, opts.AllowNodeOverlap)
	if !ok {
		return Solution{}, fmt.Errorf("no arrangement of boxes and nodes found on a %dx%d grid with the chosen sizes", config.GridW, config.GridH)
	}

	allowed := finalPossibleCells(placedBoxes, nodes, nodeToBoxes, &config)

	for _, n := range nodes {
		if len(allowed[n.ID]) == 0 {
			return Solution{}, fmt.Errorf("no allowed position for node %s after boxes placed", n.ID)
		}
	}

	assign, ok := assignNodes(nodes, allowed, &config, opts.AllowNodeOverlap)
	if !ok {
		return Solution{}, fmt.Errorf("couldn't assign nodes to distinct cells (try SolveOptions{AllowNodeOverlap: true} or expand grid)")
	}

	placedNodes := []PlacedNode{}
	for _, n := range nodes {
		idx := assign[n.ID]
		x, y := encodeXY(idx, &config)
		placedNodes = append(placedNodes, PlacedNode{ID: n.ID, X: x, Y: y})
	}

	return Solution{Boxes: placedBoxes, Nodes: placedNodes, memberships: memberships, config: config}, nil
}

// SolveModel creates a placement solution for a list of assets and trust boundaries from the common threat model.
func SolveModel(assets []common.Asset, boundaries []common.TrustBoundary, config SolverConfig, opts SolveOptions) (Solution, error) {
	return SolveModelWithFixedElements(assets, boundaries, nil, nil, config, opts)
}

// SolveModelWithFixedElements converts the threat model into solver inputs and runs Solve.
// fixedAssets pins existing unchanged assets at their current diagram positions.
// fixedBoundaries pins existing trust boundaries at their current diagram positions.
// Both maps are keyed by element ID and may be nil (treated as empty).
// PlacedBox.X/Y are the top-left corner in diagram space; W and H are the actual cell
// dimensions. The translation to solver coordinates uses the real size so no approximation
// is needed.
func SolveModelWithFixedElements(assets []common.Asset, boundaries []common.TrustBoundary, fixedAssets map[string]PlacedBox, fixedBoundaries map[string]PlacedBox, config SolverConfig, opts SolveOptions) (Solution, error) {
	nodeDefs := make([]NodeDef, 0, len(assets))
	for _, asset := range assets {
		nodeDef := NodeDef{ID: asset.ID}
		if fe, ok := fixedAssets[asset.ID]; ok {
			// diagram top-left → solver cell centre:
			//   GetPosition output: pos.X = node.X - W/2 + globalOffsetX
			//   → node.X = pos.X + W/2 - globalOffsetX
			// Snap to nearest cell centre by subtracting half a cell before rounding.
			nodeDef.Fixed = true
			centreX := float64(fe.X) + float64(fe.W)/2 - config.GlobalOffsetX
			centreY := float64(fe.Y) + float64(fe.H)/2 - config.GlobalOffsetY
			nodeDef.X = int(math.Round((centreX-config.GridSizeX/2)/config.GridSizeX))*int(config.GridSizeX) + int(config.GridSizeX)/2
			nodeDef.Y = int(math.Round((centreY-config.GridSizeY/2)/config.GridSizeY))*int(config.GridSizeY) + int(config.GridSizeY)/2
		}
		nodeDefs = append(nodeDefs, nodeDef)
	}

	boxDefs := make([]BoxDef, 0, len(boundaries))
	memberships := make([]Membership, 0, len(assets)) // len(assets) is only an estimate
	for _, boundary := range boundaries {
		boxDef := BoxDef{ID: boundary.ID, Fixed: false}

		if fe, ok := fixedBoundaries[boundary.ID]; ok {
			// diagram top-left → solver box origin:
			//   GetBoundaryPosition output: pos.X = box.X + globalOffsetX
			//   → box.X = pos.X - globalOffsetX
			boxDef.Fixed = true
			boxDef.X = int(math.Round((float64(fe.X)-config.GlobalOffsetX)/config.GridSizeX)) * int(config.GridSizeX)
			boxDef.Y = int(math.Round((float64(fe.Y)-config.GlobalOffsetY)/config.GridSizeY)) * int(config.GridSizeY)
			boxDef.W = int(math.Round(float64(fe.W)/config.GridSizeX)) * int(config.GridSizeX)
			boxDef.H = int(math.Round(float64(fe.H)/config.GridSizeY)) * int(config.GridSizeY)
		}

		for _, containedAssetID := range boundary.ContainedAssets {
			memberships = append(memberships, Membership{
				BoxID:  boundary.ID,
				NodeID: containedAssetID,
			})
		}

		boxDefs = append(boxDefs, boxDef)
	}

	return Solve(boxDefs, nodeDefs, memberships, config, opts)
}

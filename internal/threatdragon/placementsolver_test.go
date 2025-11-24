package threatdragon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			got, err := Solve(tt.boxDefs, tt.nodeDefs, tt.memberships)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Sanity: number of results should match expectations
				assert.Len(t, got.Boxes, tt.expectBoxes)
				assert.Len(t, got.Nodes, tt.expectNodes)

				// All placed entities must be within grid bounds
				for _, b := range got.Boxes {
					if b.X < 0 || b.Y < 0 || b.X+b.W > GRID_W || b.Y+b.H > GRID_H {
						t.Errorf("box %s out of bounds: %+v", b.ID, b)
					}
				}
				for _, n := range got.Nodes {
					if n.X < 0 || n.Y < 0 || n.X >= GRID_W || n.Y >= GRID_H {
						t.Errorf("node %s out of bounds: %+v", n.ID, n)
					}
				}
			}
		})
	}
}

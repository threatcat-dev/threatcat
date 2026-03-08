// Package dataflow provides parsers for extracting data flow definitions from multiple sources.
//
// The package supports two parsing strategies:
//  1. Comment-based parsing: Extracts flows from specially formatted comments in Docker Compose files
//     Format: #(source)<arrow>(target);Name;Protocol;Encrypted;Public
//     Arrows: -->, <--, <-->
//  2. YAML-based parsing: Parses dedicated YAML files with structured data flow definitions
//
// Both parsers produce common.DataFlow objects that can be integrated into threat models.

package dataflow

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/threatcat-dev/threatcat/internal/common"
)

type DataflowCommentParser struct {
	filePath string
	logger   *slog.Logger
}

func NewDataflowCommentParser(filePath string, logger *slog.Logger) *DataflowCommentParser {
	return &DataflowCommentParser{
		filePath: filePath,
		logger:   logger.With("package", "dataflow", "component", "DataflowCommentParser"),
	}
}

func ParseAndConvert(filePaths []string, tModels []common.ThreatModel, logger *slog.Logger) (*common.ThreatModel, error) {
	var dataflows []common.DataFlow
	//Create full list of all dataflows with ids
	for _, filePath := range filePaths {
		dfcp := NewDataflowCommentParser(filePath, logger)
		dftmp, err := dfcp.parseDataFlows()
		if err != nil {
			return nil, fmt.Errorf("failed to parse docker compose yaml: %w", err)
		}
		dataflows = append(dataflows, dftmp...)
	}

	for _, tModel := range tModels {
		ReplaceAssetNamesWithIDs(dataflows, tModel.Assets, logger) //not sure if it is the best solution
	}

	tModel := common.EmptyThreatModel()
	tModel.DataFlows = dataflows

	return &tModel, nil
}

// ParseDataFlows loads a docker-compose file and extracts comment-based dataflows.
// Malformed lines are skipped (with debug logging).
func (a *DataflowCommentParser) parseDataFlows() ([]common.DataFlow, error) {
	lines, err := a.readComments(a.filePath)
	if err != nil {
		return nil, err
	}

	var flows []common.DataFlow
	for _, l := range lines {
		df, ok := a.parseSingleDataFlow(l)
		if ok {
			flows = append(flows, df)
		}
	}
	return flows, nil
}

// readComments keeps only lines containing "#".
func (a *DataflowCommentParser) readComments(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "#") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out, sc.Err()
}

// parseSingleDataFlow parses a single comment line.
// Expected format: #(asset1)<dir>(asset2);Name;Protocol;Encrypted;Public
func (a *DataflowCommentParser) parseSingleDataFlow(line string) (common.DataFlow, bool) {
	hashIdx := strings.Index(line, "#(")
	if hashIdx == -1 {
		return common.DataFlow{}, false
	}

	// Remove "#" prefix
	line = strings.TrimSpace(line[1:])

	// Split on first ";": left contains "(asset)-->(asset)", rest is metadata slice
	parts := strings.Split(line, ";")
	if len(parts) == 0 {
		return common.DataFlow{}, false
	}

	mainPart := parts[0]
	meta := parts[1:]

	asset1, arrow, asset2, ok := extractAssetsArrow(mainPart)
	if !ok {
		a.logger.Warn("Failed to parse asset/direction section", slog.String("input", line))
		return common.DataFlow{}, false
	}

	backwards, bidirectional := parseDirection(arrow)

	if backwards {
		asset1, asset2 = asset2, asset1
	}

	df := common.DataFlow{
		Source:            asset1,
		Target:            asset2,
		Bidirectional:     bidirectional,
		Threats:           []common.Threat{},
		DataSource:        common.DataSourceDockerCompose,
		IsGeneratedByUser: false,
	}

	a.parseMeta(meta, &df)

	return df, true
}

// extractAssetsArrow parses something like "(a)-->(b)".
// Returns asset1, arrowString, asset2, ok.
func extractAssetsArrow(s string) (string, string, string, bool) {
	// first pair "(...)" = asset1
	l1 := strings.Index(s, "(")
	r1 := strings.Index(s, ")")
	if l1 == -1 || r1 == -1 || r1 < l1 {
		return "", "", "", false
	}
	asset1 := s[l1+1 : r1]

	rest := s[r1+1:]

	// second pair "(...)" = asset2
	l2 := strings.Index(rest, "(")
	r2 := strings.Index(rest, ")")
	if l2 == -1 || r2 == -1 || r2 < l2 {
		return "", "", "", false
	}
	asset2 := rest[l2+1 : r2]

	arrow := strings.TrimSpace(rest[:l2])

	return asset1, arrow, asset2, true
}

// parseDirection maps arrows to two bools (backwards and bidirectional).
// Allowed: -->, <--, <-->
func parseDirection(arrow string) (bool, bool) {
	switch arrow {
	case "<-->":
		return false, true
	case "-->":
		return false, false
	case "<--":
		return true, false
	default:
		// fallback if invalid
		return false, false
	}
}

// parseMeta fills Name, Protocol, Encrypted, PublicNetwork from meta fields.
func (a *DataflowCommentParser) parseMeta(parts []string, df *common.DataFlow) {
	// defaults
	df.Name = ""
	df.Protocol = ""
	df.Encrypted = false
	df.PublicNetwork = false

	// expected 4 fields: name, protocol, encrypted?, public?
	if len(parts) < 4 {
		a.logger.Warn("Not enough field in data flow comment", "parts", parts)
		return
	}

	df.Name = parts[0]
	df.ID = common.GenerateIDHashFromFilePath(a.filePath, df.Name)
	df.Protocol = parts[1]

	if strings.EqualFold(parts[2], "encrypted") {
		df.Encrypted = true
	} else if !strings.EqualFold(parts[2], "unencrypted") {
		a.logger.Warn("Unexpected encryption field", "value", parts[2])
	}

	pub := strings.ToLower(parts[3])
	if pub == "public" || pub == "publicnetwork" {
		df.PublicNetwork = true
	} else if pub != "private" && pub != "privatenetwork" {
		a.logger.Warn("Unexpected public/private network field", "value", parts[3])
	}
}

package boundaries

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

func TestDebugPlacement(t *testing.T) {
	const (
		composeFile = "./input.docker-compose.yaml"
		outputPath  = "/tmp/debug_placement.json"
	)
	defer os.Remove(outputPath)

	dockerImageMap, err := dockercompose.NewDockerImageMap("")
	if err != nil {
		t.Fatal(err)
	}

	parser := dockercompose.NewDockerComposeParser(composeFile, slog.Default())
	analyzer := dockercompose.NewDockerComposeAnalyzer(composeFile, slog.Default())

	parsed, err := parser.ParseDockerComposeYML()
	if err != nil {
		t.Fatal(err)
	}

	initialModel, err := analyzer.Analyze(parsed, dockerImageMap)
	if err != nil {
		t.Fatal(err)
	}

	output := threatdragon.NewThreatdragonOutput(outputPath, dummyChangelog{}, slog.Default())
	if err := output.Generate(initialModel); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(outputPath)
	var raw map[string]any
	json.Unmarshal(data, &raw)

	detail := raw["detail"].(map[string]any)
	diagrams := detail["diagrams"].([]any)
	cells := diagrams[0].(map[string]any)["cells"].([]any)

	for _, c := range cells {
		cell := c.(map[string]any)
		pos := cell["position"].(map[string]any)
		size := cell["size"].(map[string]any)
		data := cell["data"].(map[string]any)
		name := ""
		if n, ok := data["name"].(string); ok {
			name = n
		}
		cellType := data["type"].(string)
		fmt.Printf("%-20s %-20s pos=(%.0f,%.0f) size=(%.0f×%.0f)\n",
			cellType, name,
			pos["x"].(float64), pos["y"].(float64),
			size["width"].(float64), size["height"].(float64))
	}
}

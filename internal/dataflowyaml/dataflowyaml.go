package dataflowyaml

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/threatcat-dev/threatcat/internal/common"
	"gopkg.in/yaml.v3"
)

type DataflowYamlParser struct {
	filePath string
	logger   *slog.Logger
}

func NewDataflowYamlParser(filePath string, logger *slog.Logger) *DataflowYamlParser {
	return &DataflowYamlParser{
		filePath: filePath,
		logger:   logger.With("package", "dataflowyaml", "component", "DataflowYamlParser"),
	}
}

func (dfyp *DataflowYamlParser) ParseAndConvert() (*common.ThreatModel, error) {
	dataflows, err := dfyp.parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse dataflows yaml: %w", err)
	}

	err = dfyp.validate(dataflows)
	if err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	dfyp.generateIDs(dataflows)

	tModel := common.EmptyThreatModel()
	tModel.DataFlows = dataflows

	return &tModel, nil
}

// parse reads the YAML file and unmarshals its dataflows section.
func (dfyp *DataflowYamlParser) parse() ([]common.DataFlow, error) {
	dfyp.logger.Debug("Opening dataflows file for parsing", "filePath", dfyp.filePath)
	file, err := os.Open(dfyp.filePath)
	if err != nil {
		dfyp.logger.Error("Failed to open file", "filePath", dfyp.filePath, "error", err)
		return nil, err
	}
	defer file.Close()

	dfyp.logger.Debug("File opened, decoding content", "filePath", dfyp.filePath)

	var config yamlContent
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		dfyp.logger.Error("Failed to decode dataflows yaml content", "filePath", dfyp.filePath, "error", err)
		return nil, err
	}

	dfyp.logger.Debug("YAML decoded successfully", "dataFlowsCount", len(config.DataFlows))

	return config.DataFlows, nil
}

func (dfyp *DataflowYamlParser) validate(dataflows []common.DataFlow) error {
	seenNames := make(map[string]struct{})

	for _, flow := range dataflows {
		// Name must not be empty
		if flow.Name == "" {
			return fmt.Errorf("dataflow name must not be empty")
		}

		// Name must not be duplicate
		if _, ok := seenNames[flow.Name]; ok {
			return fmt.Errorf("duplicate dataflow name: %s", flow.Name)
		}

		seenNames[flow.Name] = struct{}{}
	}

	return nil
}

func (dfyp *DataflowYamlParser) generateIDs(dataflows []common.DataFlow) {
	for i, flow := range dataflows {
		dataflows[i].ID = common.GenerateIDHash(dfyp.filePath, flow.Name)
	}
}

type yamlContent struct {
	DataFlows []common.DataFlow `yaml:"dataflows"`
}

package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/threatcat-dev/threatcat/internal/changelog"
	"github.com/threatcat-dev/threatcat/internal/common"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/logging"
	"github.com/threatcat-dev/threatcat/internal/modelmerger"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

func main() {
	//print logo

	// read, validate and print user arguments
	cmd := readArguments()
	err := cmd.validate()
	if err != nil {
		log.Fatalf("Invalid arguments: %v\n", err)
	}

	if cmd.SilentMode {
		os.Stdout = os.NewFile(0, os.DevNull)
	}
	fmt.Println(threatCatLogo)

	cmd.print()

	// set up logging
	fmt.Println("[1/7] 📋  Set up logging")
	level := slog.LevelInfo
	if cmd.LogOpts.Verbose {
		level = slog.LevelDebug
	}
	var logger *slog.Logger
	if cmd.SilentMode {
		if cmd.LogOpts.LogFilePath != "" {
			logger, err = logging.NewFileLogger(cmd.LogOpts.LogFilePath, level)
			if err != nil {
				log.Fatalf("Could not setup logger: %v", err)
			}
		} else {
			logger = logging.NewDiscardLogger()
		}

	} else if cmd.LogOpts.LogFilePath == "" {
		// if no log file path is provided, use console logger
		logger = logging.NewConsoleLogger(level)
	} else {
		// if a log file path is provided, use dual logger (console + file)
		logger, err = logging.NewDualLogger(cmd.LogOpts.LogFilePath, level)
		if err != nil {
			log.Fatalf("Could not setup logger: %v", err)
		}
	}
	slog.SetDefault(logger)

	fmt.Println("[2/7] 📂  Handle Config files")
	// handle docker image map config file
	dockerImageMap, err := dockercompose.NewDockerImageMap(cmd.ConfigFiles.DockerImageMapConfig)
	if err != nil {
		log.Fatalf("Could not handle Docker Image Map Config file: %v", err)
	}

	// set changelog instance
	cl := changelog.NewChangelog(logger)

	fmt.Println("[3/7] 🔍  Parse and analyze input files")
	threatModels, err := parseAndAnalyzeInputFiles(cmd.InFiles, dockerImageMap, logger)
	if err != nil {
		log.Fatalf("Could not analyze input files")
	}

	fmt.Println("[4/7] 🛠️  Merging models")
	modelMerger := modelmerger.NewModelMerger(cl, logger)
	merged := modelMerger.Merge(threatModels)

	fmt.Println("[5/7] 💾  Generating output model")
	output := threatdragon.NewThreatdragonOutput(cmd.OutFilePath, cl, logger)
	err = output.Generate(&merged)
	if err != nil {
		log.Fatalf("Could not generate output threat model to requested filepath: %s err: %v", cmd.OutFilePath, err)
	}

	// Am Ende: Changelog schreiben
	fmt.Println("[6/7] 💾  Generating Changelog")
	// write changelog to file
	if cmd.ChangelogPath != "" {
		cl.AddEntry("_______________")
		// new function - writes changelog in bottom up style - Markdown format
		err = cl.OutputTo(cmd.ChangelogPath)
		if err != nil {
			fmt.Println("Error while writing the changelog:", err)
		}
	}

	fmt.Print("[7/7] ✅  Done!")
}

// helper to parse and analyze docker compose files
func parseAndAnalyzeDockerComposeFiles(filePath string, dockerImageMap dockercompose.DockerImageMap, logger *slog.Logger) (*common.ThreatModel, error) {
	parser := dockercompose.NewDockerComposeParser(filePath, logger)
	parsed, err := parser.ParseDockerComposeYML()
	if err != nil {
		return nil, fmt.Errorf("failed to parse DockerCompose file: %s err: %w", filePath, err)
	}

	analyzer := dockercompose.NewDockerComposeAnalyzer(filePath, logger)
	tModel, err := analyzer.Analyze(parsed, dockerImageMap)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze DockerCompose file %s err: %w", filePath, err)
	}

	return tModel, nil
}

// helper to parse and analyze threat dragon files
func parseAndAnalyzeThreatDragonFile(filePath string, logger *slog.Logger) (*common.ThreatModel, error) {
	// parse threat dragon file
	parsed := threatdragon.NewThreatDragonInput(filePath, logger)

	// analyze threat dragon file
	tModel, err := parsed.Analyze()
	if err != nil {
		return nil, fmt.Errorf("could not analyze ThreatDragon file %s err: %w", filePath, err)
	}

	return tModel, nil
}

// Parse/Analyze all input files provided by user
func parseAndAnalyzeInputFiles(inFiles inputFiles, dockerImageMap dockercompose.DockerImageMap, logger *slog.Logger) ([]common.ThreatModel, error) {
	logger = logger.With("package", "main")
	var threatModels []common.ThreatModel
	// handle docker compose files
	for _, dcmpFile := range inFiles.DockerComposeFiles {
		logger.Info("Parsing and analyzing docker-compose file", "filepath", dcmpFile)
		tModel, err := parseAndAnalyzeDockerComposeFiles(dcmpFile, dockerImageMap, logger)
		if err != nil {
			return nil, fmt.Errorf("could not analyze DockerCompose File: %s err: %v", dcmpFile, err)
		}
		threatModels = append(threatModels, *tModel)
		logger.Info("Successfully parsed and  analyzed docker-compose file", "filepath", dcmpFile)
	}
	// handle threat dragon files
	for _, tdFile := range inFiles.ThreatDragonFiles {
		logger.Info("Parsing and analyzing ThreatDragon file", "filepath", tdFile)
		tModel, err := parseAndAnalyzeThreatDragonFile(tdFile, logger)
		if err != nil {
			return nil, fmt.Errorf("could not analyze ThreatDragon File: %s err: %v", tdFile, err)
		}
		threatModels = append(threatModels, *tModel)
		logger.Info("Successfully parsed and analyzed ThreatDragon file", "filepath", tdFile)
	}
	// confirm that atleast one threat models was created
	if len(threatModels) == 0 {
		return nil, errors.New("analyzing failed: no input files detected")
	}

	return threatModels, nil
}

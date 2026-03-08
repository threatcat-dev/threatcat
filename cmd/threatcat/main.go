// Package main provides the entry point for ThreatCat, a CLI tool designed to
// automate threat model creation and maintenance.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/threatcat-dev/threatcat/internal/changelog"
	"github.com/threatcat-dev/threatcat/internal/common"
	"github.com/threatcat-dev/threatcat/internal/dataflow"
	"github.com/threatcat-dev/threatcat/internal/dockercompose"
	"github.com/threatcat-dev/threatcat/internal/logging"
	"github.com/threatcat-dev/threatcat/internal/modelmerger"
	"github.com/threatcat-dev/threatcat/internal/threatdragon"
)

// threatCatLogo contains the ASCII art logo displayed on startup.
var threatCatLogo string = `
               #                          #
               ##-                      -##       
               ####+                  +####       
               #######-  -------   -#######       
               ############################       
               ############################       
               ############################       
               ### -##################- ###       
               ###   +++ ######## +++   ###       
               ###+       ######       +###       
               -######++###########++#####-       
                -##########    #########-        
                  -#########  #########-          
                    -###############-            
                        -++####++-          
			  
   ######## ##  ##  ######   ######     ##   ######## 
      ##    ##  ##  ##   ##  ##        ####     ##        
      ##    ######  ######   ######   ##  ##    ##        
      ##    ##  ##  ##  ##   ##      ########   ##        
      ##    ##  ##  ##   ##  ######  ##    ##   ##        
                                                            
            	######     ###  ########                  
               ###   ##   ## ##    ##                     
              ###        ##   ##   ##                     
               ###   ## #########  ##                     
                ######  ##     ##  ##                     
`

// threatCatVersion holds the application version.
var threatCatVersion string = "1.0.0"

// Exit codes returned by the application on different error conditions.
const (
	ExitSuccess           = 0   // Indicates the program completed successfully
	FatalErrorInvalidArgs = 1   // Invalid command-line arguments
	FatalErrorFile        = 2   // File operation error (read/write)
	FatalErrorProcessing  = 3   // Error during threat model processing
	FatalErrorSetup       = 4   // Error during initialization (logger, etc.)
	ExitInterrupt         = 130 // Standard exit code for SIGINT (128 + 2)
)

// main acts as the primary orchestrator for the ThreatCat CLI. It executes a
// multi-step pipeline: initializing signal handling, parsing and validating
// user arguments, setting up logging, and processing infrastructure-as-code
// files into a unified threat model. It concludes by merging models,
// generating a Threat Dragon-compatible output, and optionally exporting a
// changelog.
func main() {

	// init OS Signal Handler
	setupSignalHandling()

	// read, validate and print user arguments
	cmd := readArguments()
	err := cmd.validate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid arguments: %v\n", err)
		os.Exit(FatalErrorInvalidArgs)
	}
	// If version is requested, print it and exit
	if cmd.Version {
		fmt.Println("ThreatCat version", threatCatVersion)
		os.Exit(ExitSuccess)
	}

	// disable prints if silent mode is activated
	if cmd.SilentMode {
		devNull, err := os.Open(os.DevNull)
		if err == nil {
			os.Stdout = devNull
		}
	} else {
		//print logo and registered user arguments
		fmt.Println(threatCatLogo)
		cmd.print()
	}

	// set up logging
	fmt.Println("[1/7] 📋  Set up logging")
	logger, cleanup, err := setupLogger(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not setup logger: %v\n", err)
		os.Exit(FatalErrorSetup)
	}
	if cleanup != nil {
		defer func() {
			if err := cleanup(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close log file: %v\n", err)
			}
		}()
	}

	// set changelog instance
	cl := changelog.NewChangelog(logger)
	defer cl.Close()

	fmt.Println("[2/7] 📂  Handle config files")
	dockerImageMap, err := dockercompose.NewDockerImageMap(cmd.ConfigFiles.DockerImageMapConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not handle docker image map config file: %v\n", err)
		os.Exit(FatalErrorProcessing)
	}

	fmt.Println("[3/7] 🔍  Parse and analyze input files")
	threatModels, err := parseAndAnalyzeInputFiles(cmd.InFiles, dockerImageMap, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not analyze input files: %v\n", err)
		os.Exit(FatalErrorProcessing)
	}

	InputFiles := append(append(cmd.InFiles.DockerComposeFiles,
		cmd.InFiles.ThreatDragonFiles...),
		cmd.InFiles.DataFlowYamlFiles...)

	for _, file := range InputFiles {
		if err := cl.AddCommitInfo(file); err != nil {
			fmt.Fprintf(os.Stderr, "Changelog commit info error: %v\n", err)
			os.Exit(FatalErrorProcessing)
		}
	}

	fmt.Println("[4/7] 🛠️  Merging models")
	modelMerger := modelmerger.NewModelMerger(cl, logger, cmd.ManualMode)
	merged := modelMerger.Merge(threatModels)

	fmt.Println("[5/7] 🧩  Generating output model")
	output := threatdragon.NewThreatdragonOutput(cmd.OutFilePath, cl, logger)
	err = output.Generate(&merged)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not generate output threat model to requested filepath: %s err: %v", cmd.OutFilePath, err)
		os.Exit(FatalErrorFile)
	}

	fmt.Println("[6/7] 💾  Generating changelog")
	// write changelog to file
	if cmd.ChangelogPath != "" {
		cl.AddEntry("_______________")
		// new function - writes changelog in bottom up style - Markdown format
		err = cl.OutputTo(cmd.ChangelogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while writing the changelog: %v", err)
			os.Exit(FatalErrorFile)
		}
	}

	fmt.Print("[7/7] ✅  Done!")
}

// Sets up graceful handling of OS signals (SIGTERM, SIGINT)

func setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	// Notify handles both Ctrl+C (Interrupt) and termination signals
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt, shutting down...")
		os.Exit(ExitInterrupt)
	}()
}

// Sets up logger based on configured arguments
func setupLogger(cmd userArguments) (*slog.Logger, func() error, error) {

	level := slog.LevelInfo
	if cmd.LogOpts.Verbose {
		level = slog.LevelDebug
	}

	var logger *slog.Logger
	var cleanup func() error
	var err error

	path := cmd.LogOpts.LogFilePath

	switch {
	case cmd.SilentMode && (path != ""):
		logger, cleanup, err = logging.NewFileLogger(path, level)

	case cmd.SilentMode && (path == ""):
		logger = logging.NewDiscardLogger()

	case path == "":
		logger = logging.NewConsoleLogger(level)

	default:
		logger, cleanup, err = logging.NewDualLogger(path, level)
	}

	if err != nil {
		return nil, nil, err
	}

	slog.SetDefault(logger)

	return logger, cleanup, nil
}

// parseAndAnalyzeDockerComposeFiles parses and analyzes a single docker compose file.
// It returns a ThreatModel or an error if parsing or analysis fails.
func parseAndAnalyzeDockerComposeFile(filePath string, dockerImageMap dockercompose.DockerImageMap, logger *slog.Logger) (*common.ThreatModel, error) {
	parser := dockercompose.NewDockerComposeParser(filePath, logger)
	parsed, err := parser.ParseDockerComposeYML()
	if err != nil {
		return nil, fmt.Errorf("failed to parse docker compose file: %s err: %w", filePath, err)
	}
	analyzer := dockercompose.NewDockerComposeAnalyzer(filePath, logger)

	tModel, err := analyzer.Analyze(parsed, dockerImageMap)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze docker compose file %s err: %w", filePath, err)
	}

	return tModel, nil
}

// parseAndAnalyzeCommentsInDockerComposeFiles parses and analyzes dataflow related comments in a single docker compose file.
// It returns a ThreatModel or an error if parsing or analysis fails.
func parseAndAnalyzeCommentsInDockerComposeFile(filePaths []string, tModels []common.ThreatModel, logger *slog.Logger) (*common.ThreatModel, error) {
	tModel, err := dataflow.ParseAndConvert(filePaths, tModels, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to parse dataflows from comment: %w", err)
	}
	return tModel, nil
}

// parseAndAnalyzeThreatDragonFile parses and analyzes comments in a single threat dragon file.
// It returns a ThreatModel or an error if parsing or analysis fails.
func parseAndAnalyzeThreatDragonFile(filePath string, logger *slog.Logger) (*common.ThreatModel, error) {
	// parse threat dragon file
	parsed := threatdragon.NewThreatDragonInput(filePath, logger)

	// analyze threat dragon file
	tModel, err := parsed.Analyze()
	if err != nil {
		return nil, fmt.Errorf("could not analyze threat dragon file %s err: %w", filePath, err)
	}

	return tModel, nil
}

// parseDataflowYamlFile parses and analyzes a single dataflow yaml file.
// It returns a ThreatModel or an error if parsing or analysis fails.
func parseDataflowYamlFile(filePath string, tModels []common.ThreatModel, logger *slog.Logger) (*common.ThreatModel, error) {
	parser := dataflow.NewDataflowYamlParser(filePath, logger)

	tModel, err := parser.ParseAndConvert(tModels)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and convert dataflow yaml file %s err: %w", filePath, err)
	}

	return tModel, nil
}

// parseFilesToThreatModels iterates through a slice of paths, parses each file via specified parsing function,
// and appends the resulting models to the provided master slice.
func parseFilesToThreatModels(
	aggregatedModels *[]common.ThreatModel,
	label string,
	paths []string,
	logger *slog.Logger,
	parseFn func(string) (*common.ThreatModel, error),
) error {
	for _, path := range paths {
		logger.Info(fmt.Sprintf("Parsing and analyzing %s", label), "filepath", path)

		tModel, err := parseFn(path)
		if err != nil {
			return fmt.Errorf("could not analyze %s: %s err: %w", label, path, err)
		}

		// Append directly to the master list via pointer
		*aggregatedModels = append(*aggregatedModels, *tModel)

		logger.Info(fmt.Sprintf("Successfully parsed and analyzed %s", label), "filepath", path)
	}
	return nil
}

// parseAndAnalyzeInputFiles processes all provided input files—including docker compose files,
// threat dragon, and dataflow yamls to generate a consolidated slice of threat models.
// It performs inline comment analysis on Docker Compose files and validates that at least
// one threat model is produced. If any parsing or analysis step fails, it returns an error.
func parseAndAnalyzeInputFiles(inFiles inputFiles, dockerImageMap dockercompose.DockerImageMap, logger *slog.Logger) ([]common.ThreatModel, error) {
	logger = logger.With("package", "main")

	// Pre allocate threatModels to reduce memory reallocations
	totalExpected := len(inFiles.DockerComposeFiles) + len(inFiles.ThreatDragonFiles) + len(inFiles.DataFlowYamlFiles) + 1
	threatModels := make([]common.ThreatModel, 0, totalExpected)

	// Parse docker compose Files
	err := parseFilesToThreatModels(&threatModels, "docker compose file", inFiles.DockerComposeFiles, logger,
		func(p string) (*common.ThreatModel, error) {
			return parseAndAnalyzeDockerComposeFile(p, dockerImageMap, logger)
		})
	if err != nil {
		return nil, err
	}

	// handle threat dragon files
	err = parseFilesToThreatModels(&threatModels, "threat dragon file", inFiles.ThreatDragonFiles, logger,
		func(p string) (*common.ThreatModel, error) {
			return parseAndAnalyzeThreatDragonFile(p, logger)
		})
	if err != nil {
		return nil, err
	}

	// handle docker compose inline comments
	if len(inFiles.DockerComposeFiles) > 0 {
		logger.Info("Parsing and analyzing docker-compose files for data flow comments")
		tModel, err := parseAndAnalyzeCommentsInDockerComposeFile(inFiles.DockerComposeFiles, threatModels, logger)
		if err != nil {
			return nil, fmt.Errorf("could not analyze comments: %w", err)
		}
		threatModels = append(threatModels, *tModel)
	}

	// parse data flow yaml files
	err = parseFilesToThreatModels(&threatModels, "dataflow yaml file", inFiles.DataFlowYamlFiles, logger,
		func(p string) (*common.ThreatModel, error) {
			return parseDataflowYamlFile(p, threatModels, logger)
		})
	if err != nil {
		return nil, err
	}

	// confirm that atleast one threat models was created
	if len(threatModels) == 0 {
		return nil, errors.New("analyzing failed: no input files detected")
	}

	return threatModels, nil
}

// This file implements command-line argument handling for threatcat

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"
)

// Struct to organise input files
type inputFiles struct {
	DockerComposeFiles []string
	ThreatDragonFiles  []string
	DataFlowYamlFiles  []string
}

// Arguments to initialize logger
type loggingOptions struct {
	Verbose     bool
	LogFilePath string
}

// Config files related arguments
type configFileOptions struct {
	DockerImageMapConfig string
}

// Struct that holds parsed user args
type userArguments struct {
	LogOpts       loggingOptions
	InFiles       inputFiles
	OutFilePath   string
	SilentMode    bool
	ManualMode    bool
	Version       bool
	ConfigFiles   configFileOptions
	ChangelogPath string
}

// readArguments parses the command line flags into a userArguments struct.
// It uses pflag for POSIX-compliant flag handling.
func readArguments() userArguments {
	var args userArguments

	//input file related arguments
	pflag.StringSliceVarP(&args.InFiles.DockerComposeFiles, "dockercompose", "d", []string{}, "Indicates a docker compose input file")
	pflag.StringSliceVarP(&args.InFiles.ThreatDragonFiles, "threatdragon", "t", []string{}, "Indicates a threat dragon input file")
	pflag.StringSliceVarP(&args.InFiles.DataFlowYamlFiles, "dataflow", "w", []string{}, "Define path to data flow input file")
	//threat model output file related arguments
	pflag.StringVarP(&args.OutFilePath, "output", "o", "out.json", "Define output filepath")
	//logging related arguments
	pflag.BoolVarP(&args.LogOpts.Verbose, "verbose", "v", false, "Enable verbose logging")
	pflag.StringVarP(&args.LogOpts.LogFilePath, "logfile", "f", "", "Define path to log file")
	//silent mode
	pflag.BoolVarP(&args.SilentMode, "silent", "s", false, "Enable silent mode")
	//manual mode
	pflag.BoolVarP(&args.ManualMode, "manual", "m", false, "Enable manual model merging")
	// display version
	pflag.BoolVarP(&args.Version, "version", "V", false, "Display version")
	//config file related arguments
	pflag.StringVarP(&args.ConfigFiles.DockerImageMapConfig, "imagemap", "i", "", "Define path to docker image map config file")
	//changelog output path
	pflag.StringVarP(&args.ChangelogPath, "changelog", "c", "", "Define path to changelog file")
	pflag.Parse()

	return args
}

// validate ensures the provided userArguments are logically sound and that
// all specified file paths are accessible.
func (a userArguments) validate() error {

	// if version flag is set, skip checking other flags
	if a.Version {
		return nil
	}

	// check if at least one input file is provided
	if len(a.InFiles.DockerComposeFiles) == 0 && len(a.InFiles.ThreatDragonFiles) == 0 {
		return fmt.Errorf("at least one input file must be provided")
	}

	// check if output file path is provided
	if a.OutFilePath == "" {
		return fmt.Errorf("output file path must be provided")
	}

	// check if the input files are valid file paths and exist
	for _, fpath := range a.InFiles.DockerComposeFiles {
		if !validInputPath(fpath) {
			return fmt.Errorf("invalid docker compose file path: %s", fpath)
		}
	}
	for _, fpath := range a.InFiles.ThreatDragonFiles {
		if !validInputPath(fpath) {
			return fmt.Errorf("invalid threat dragon file path: %s", fpath)
		}
	}
	for _, fpath := range a.InFiles.DataFlowYamlFiles {
		if !validInputPath(fpath) {
			return fmt.Errorf("invalid dataflow file path: %s", fpath)
		}
	}

	// check if the output file path is valid
	if !validOutputPath(a.OutFilePath) {
		return fmt.Errorf("invalid output file path: %s", a.OutFilePath)
	}

	// if a log file path is provided, check if it is valid
	if a.LogOpts.LogFilePath != "" && !validOutputPath(a.LogOpts.LogFilePath) {
		return fmt.Errorf("invalid log file path: %s", a.LogOpts.LogFilePath)
	}

	if a.ConfigFiles.DockerImageMapConfig != "" && !validInputPath(a.ConfigFiles.DockerImageMapConfig) {
		return fmt.Errorf("invalid docker image file path: %s", a.ConfigFiles.DockerImageMapConfig)

	}
	// silent mode can not be used alongside manual mode, since it will block commandline messages to user
	if a.SilentMode && a.ManualMode {
		return fmt.Errorf("manual mode and silent mode can not be active at the same time")
	}

	return nil
}

// validInputPath checks the following criteria for input paths:
// 1. The path is not empty.
// 2. The path is a valid file path.
// 3. The file exists and is not a directory.
func validInputPath(path string) bool {
	// Clean the path to check for formatting issues
	cleanPath := filepath.Clean(path)

	// Check if path is absolute or relative
	// (This doesn't verify validity per OS-specific restrictions)
	if len(cleanPath) == 0 {
		return false
	}

	// Try accessing the file
	info, err := os.Stat(cleanPath)
	if err != nil {
		return false
	}

	// Check that it's a file, not a directory
	return !info.IsDir()
}

// isDirWritable confirms that the target directory is writable
// 1. The directory exists.
// 2. The directory is writable
func isDirWritable(dir string) bool {
	// 1. Basic check: Does it exist and is it a directory?
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	// 2. The "Honest" check: Try to create a tiny temp file
	// "" uses the default temp dir, but we specify 'dir'
	tempFile, err := os.CreateTemp(dir, ".validpathcheck")
	if err != nil {
		return false // OS denied us; directory is effectively read-only
	}

	// 3. Cleanup
	tempFileName := tempFile.Name()
	tempFile.Close()
	os.Remove(tempFileName)

	return true
}

// validOutputPath checks the following criteria for output paths:
// 1. The path is not empty.
// 2. The path is a valid file path.
// 3. The file does not exist or is writable (if it exists) and not a directory.
func validOutputPath(path string) bool {
	if path == "" {
		return false
	}

	cleanPath := filepath.Clean(path)
	info, err := os.Stat(cleanPath)

	// Case 1: The target file already exists -> check file
	if err == nil {
		if info.IsDir() {
			return false // Cannot overwrite a directory with a file
		}

		// Check if the existing file is writable without truncating/changing the file
		f, err := os.OpenFile(cleanPath, os.O_WRONLY|os.O_APPEND, 0 /* no read, no write, no execute*/)
		if err != nil {
			return false // Likely a permissions issue or file lock (Windows)
		}
		f.Close()
		return true
	}

	// Case 2: The target file does not exist -> check parent directory
	if os.IsNotExist(err) {
		parentDir := filepath.Dir(cleanPath)

		// Verify the parent directory exists first
		pInfo, pErr := os.Stat(parentDir)
		if pErr != nil || !pInfo.IsDir() {
			return false
		}

		// check whether the parent directory is writable
		return isDirWritable(parentDir)
	}

	// Case 3: Other errors occurred (e.g. permission denied)
	return false
}

// print outputs a formatted table to standard output displaying the current
// configuration state. It lists all active flags, operational modes, and
// file paths, including an expanded list of all detected input files for
// verification before processing begins.
func (a userArguments) print() {
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Printf("%-22s | %-30s\n", "Argument", "Value")
	fmt.Println("-----------------------------------------------------------------------")

	fmt.Printf("%-22s | %-30t\n", "Verbose mode", a.LogOpts.Verbose)
	fmt.Printf("%-22s | %-30t\n", "Silent mode", a.SilentMode)
	fmt.Printf("%-22s | %-30t\n", "Manual mode", a.ManualMode)
	fmt.Printf("%-22s | %-30t\n", "Display version", a.Version)
	fmt.Printf("%-22s | %-30s\n", "Log file path", a.LogOpts.LogFilePath)
	fmt.Printf("%-22s | %-30s\n", "Output file path", a.OutFilePath)
	fmt.Printf("%-22s | %-30s\n", "Docker image cfg file", a.ConfigFiles.DockerImageMapConfig)
	fmt.Printf("%-22s | %-30s\n", "Changelog path", a.ChangelogPath)
	for _, fpath := range a.InFiles.DockerComposeFiles {
		fmt.Printf("%-22s | %-30s\n", "Docker compose file", fpath)
	}
	for _, fpath := range a.InFiles.ThreatDragonFiles {
		fmt.Printf("%-22s | %-30s\n", "Threat dragon file", fpath)
	}
	for _, fpath := range a.InFiles.DataFlowYamlFiles {
		fmt.Printf("%-22s | %-30s\n", "Dataflow file path", fpath)
	}
	fmt.Println("-----------------------------------------------------------------------")
}

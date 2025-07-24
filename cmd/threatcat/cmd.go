package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/pflag"
)

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

type inputFiles struct {
	DockerComposeFiles []string
	ThreatDragonFiles  []string
}

// arguments to initialize logger
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
	ConfigFiles   configFileOptions
	ChangelogPath string
}

// read in all user aguments
func readArguments() userArguments {
	var args userArguments

	//input file related arguments
	pflag.StringSliceVarP(&args.InFiles.DockerComposeFiles, "dockercompose", "d", []string{}, "Indicates a DockerCompose input file")
	pflag.StringSliceVarP(&args.InFiles.ThreatDragonFiles, "threatdragon", "t", []string{}, "Indicates a ThreatDragon input file")
	//threat model output file related arguments
	pflag.StringVarP(&args.OutFilePath, "output", "o", "out.json", "Define Output Filepath")
	//logging related arguments
	pflag.BoolVarP(&args.LogOpts.Verbose, "verbose", "v", false, "Enable verbose logging")
	pflag.StringVarP(&args.LogOpts.LogFilePath, "logfile", "f", "", "Define path to Logfile")
	//silent mode
	pflag.BoolVarP(&args.SilentMode, "silent", "s", false, "Enable silent mode")
	//config file related arguments
	pflag.StringVarP(&args.ConfigFiles.DockerImageMapConfig, "imagemap", "i", "", "Define path to Docker Image Map Config file")
	//changelog output path
	pflag.StringVarP(&args.ChangelogPath, "changelog", "c", "", "Define path to changelog file")
	pflag.Parse()

	return args
}

func (a userArguments) validate() error {
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
			return fmt.Errorf("invalid DockerCompose file path: %s", fpath)
		}
	}
	for _, fpath := range a.InFiles.ThreatDragonFiles {
		if !validInputPath(fpath) {
			return fmt.Errorf("invalid ThreatDragon file path: %s", fpath)
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

// validOutputPath checks the following criteria for output paths:
// 1. The path is not empty.
// 2. The path is a valid file path.
// 3. The file does not exist or is writable (if it exists) and not a directory.
func validOutputPath(path string) bool {
	// Clean the path to check for formatting issues
	cleanPath := filepath.Clean(path)

	// Check if path is absolute or relative
	if len(cleanPath) == 0 {
		return false
	}

	// Try accessing the file
	info, err := os.Stat(cleanPath)
	if err != nil {
		// If the file does not exist, it's valid for output
		if os.IsNotExist(err) {
			return true
		}
		return false
	}

	// Check that it's a file, not a directory
	if info.IsDir() {
		return false
	}

	// If it exists, check if it's writable
	return info.Mode().Perm()&0200 != 0 // Check write permission
}

// pretty print user arguments
func (a userArguments) print() {
	fmt.Println("-----------------------------------------------------------------------")
	fmt.Printf("%-20s | %-30s\n", "Argument", "Value")
	fmt.Println("-----------------------------------------------------------------------")

	fmt.Printf("%-20s | %-30t\n", "verbose mode", a.LogOpts.Verbose)
	fmt.Printf("%-20s | %-30t\n", "silent mode", a.SilentMode)
	fmt.Printf("%-20s | %-30s\n", "log file path", a.LogOpts.LogFilePath)
	fmt.Printf("%-20s | %-30s\n", "output file path", a.OutFilePath)
	fmt.Printf("%-20s | %-30s\n", "docker image config file", a.ConfigFiles.DockerImageMapConfig)
	fmt.Printf("%-20s | %-30s\n", "changelog path", a.ChangelogPath)
	for _, fpath := range a.InFiles.DockerComposeFiles {
		fmt.Printf("%-20s | %-12s\n", "docker compose file", fpath)

	}

	for _, fpath := range a.InFiles.ThreatDragonFiles {
		fmt.Printf("%-20s | %-12s\n", "threat dragon file", fpath)
	}

	fmt.Println("-----------------------------------------------------------------------")
}

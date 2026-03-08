// This file implements search for repositories in git and extract git information

package changelog

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrGitNotFound is returned when the git executable cannot be found in the system PATH.
var ErrGitNotFound = errors.New("git not found")

// GitRunner abstracts git commands for testability and dependency injection.
// Implementations provide methods to query Git repository information.
type GitRunner interface {
	// RepoRoot returns the root directory of the Git repository containing the given file.
	// Returns ErrGitNotFound if git is not installed or available.
	RepoRoot(file string) (string, error)
	// CommitInfo retrieves the latest commit information from the specified repository.
	// Returns commit reference and date in a structured format.
	CommitInfo(repo string) (CommitInfo, error)
	// Close releases any resources held by the GitRunner.
	// Must be called when the GitRunner is no longer needed.
	Close() error
}

// realGitRunner is the production implementation of GitRunner that executes
// actual git commands via os/exec.
type realGitRunner struct{}

// RepoRoot determines the Git repository root directory for a given file.
// It uses 'git rev-parse --show-toplevel' to find the repository root.
//
// Returns:
//   - The absolute path to the repository root
//   - ErrGitNotFound if git is not installed
//   - An error if the file is not in a Git repository or git command fails
func (realGitRunner) RepoRoot(file string) (string, error) {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return "", ErrGitNotFound
	}

	cmd := exec.Command("git", "-C", filepath.Dir(file), "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 127 {
			return "", ErrGitNotFound
		}
		return "", fmt.Errorf("repo-root not available for %s: %w", file, err)
	}

	return strings.TrimSpace(string(out)), nil
}

// CommitInfo retrieves information about the most recent commit in the repository.
// It executes 'git log -1 --format=%D|%ci' to get the reference and date.
//
// The returned CommitInfo contains:
//   - Repo: The repository path
//   - Ref: The commit reference (branch/tag names)
//   - Date: The commit date in ISO 8601 format
//
// Returns an error if the git command fails or produces unexpected output.
func (realGitRunner) CommitInfo(repo string) (CommitInfo, error) {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return CommitInfo{}, ErrGitNotFound
	}
	cmd := exec.Command("git", "-C", repo, "log", "-1", "--format=%D|%ci")
	out, err := cmd.Output()
	if err != nil {
		return CommitInfo{}, fmt.Errorf("git log failure: %w", err)
	}

	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) != 2 {
		return CommitInfo{}, fmt.Errorf("unexpected git log output: %s", out)
	}

	return CommitInfo{
		Repo: repo,
		Ref:  parts[0],
		Date: parts[1],
	}, nil
}

// Close releases any resources held by the GitRunner.
// For realGitRunner, no persistent resources are held, so this is a no-op.
// This method exists to satisfy the GitRunner interface.
func (realGitRunner) Close() error {
	return nil
}

package changelog

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrGitNotFound = errors.New("git not found")

// GitRunner abstracts git commands (testable)
type GitRunner interface {
	RepoRoot(file string) (string, error)
	CommitInfo(repo string) (CommitInfo, error)
}

type realGitRunner struct{}

func (realGitRunner) RepoRoot(file string) (string, error) {
	cmd := exec.Command("git", "-C", filepath.Dir(file), "rev-parse", "--show-toplevel")

	if cmd.Err != nil {
		return "", ErrGitNotFound
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Repo-Root not available for %s: %w", file, err)
	}

	return strings.TrimSpace(string(out)), nil
}

func (realGitRunner) CommitInfo(repo string) (CommitInfo, error) {
	cmd := exec.Command("git", "-C", repo, "log", "-1", "--format=%D|%ci")

	if cmd.Err != nil {
		return CommitInfo{}, ErrGitNotFound
	}

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

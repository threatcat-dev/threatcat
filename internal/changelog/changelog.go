// Package changelog provides functionality for generating and managing
// changelog entries. It supports both free-form textual entries and
// automatic extraction of Git repository information from files.
//
// The package can track multiple repositories and formats changelog
// entries in markdown format, prepending new entries to existing files.
//
// Basic usage:
//
//	logger := slog.Default()
//	cl := changelog.NewChangelog(logger)
//	defer cl.Close()
//
//	cl.AddEntry("Fixed critical bug")
//	cl.AddCommitInfo("main.go")
//	cl.OutputTo("CHANGELOG.md")
package changelog

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// timestampFormat defines the format used for changelog revision timestamps.
// Uses Go's reference time format: Mon Jan 2 15:04:05 MST 2006
const timestampFormat = "2006-01-02 15:04:05"

// Changelog manages changelog entries and Git repository information.
// It collects free-form text entries and automatically extracts commit
// information from Git repositories.
//
// The Changelog is safe for sequential use but not designed for concurrent access.
// Always call Close() when done, typically via defer.
type Changelog struct {
	entries    []string     // free-form changelog messages
	repos      []CommitInfo // collected repo commit info
	logger     *slog.Logger
	git        GitRunner
	gitWarning sync.Once
}

// CommitInfo holds Git repository commit information extracted from a repository.
type CommitInfo struct {
	Repo string
	Ref  string
	Date string
}

// NewChangelog creates a new Changelog instance with the provided logger.
//
// The returned Changelog uses a realGitRunner for Git operations and should
// be closed with Close() when no longer needed to release resources.
//
// Example:
//
//	logger := slog.Default()
//	cl := changelog.NewChangelog(logger)
//	defer cl.Close()
func NewChangelog(logger *slog.Logger) *Changelog {
	return &Changelog{
		entries: []string{},
		repos:   []CommitInfo{},
		logger:  logger.With("package", "changelog"),
		git:     realGitRunner{},
	}
}

// AddEntry adds a free-form text message to the changelog.
//
// Entries are formatted as markdown list items in the final output.
// Multiple entries can be added and will appear in the order they were added.
//
// Example:
//
//	cl.AddEntry("Fixed authentication bug")
//	cl.AddEntry("Added new API endpoint")
func (cl *Changelog) AddEntry(msg string) {
	cl.entries = append(cl.entries, msg)
	cl.logger.Debug("An entry has been added to the changelog", "msg", msg)
}

// AddCommitInfo extracts Git repository information from the given file and adds it
// to the changelog's repository list.
//
// The function will:
//   - Find the Git repository containing the file
//   - Extract the latest commit information
//   - Add it to the changelog if not already present
//
// If Git is not installed or the file is not in a repository, the function
// logs a warning and returns nil (graceful degradation). Duplicate repositories
// are automatically detected and ignored.
//
// Returns an error only if the file does not exist.
func (cl *Changelog) AddCommitInfo(file string) error {
	_, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("file not found: %s", file)
	}

	repo, err := cl.git.RepoRoot(file)
	if err != nil {
		if errors.Is(err, ErrGitNotFound) {
			cl.gitWarning.Do(func() {
				cl.logger.Warn("Failed to find git executable...")
			})
			return nil
		} else {
			cl.logger.Warn("Unable to determine git repo for file. Changelog will not contain repo info.", "file", file, "err", err)
			return nil
		}
	}

	if slices.IndexFunc(cl.repos, func(ci CommitInfo) bool {
		return ci.Repo == repo
	}) >= 0 {
		// Already in list
		return nil
	}

	ci, err := cl.git.CommitInfo(repo)
	if err != nil {
		// If git is not installed, we already returned, so no need to check again.
		cl.logger.Warn("Git repo found, but failing to collect commit info.", "file", file, "err", err)
		return nil
	}

	cl.repos = append(cl.repos, ci)

	return nil
}

// OutputTo writes the changelog entries to a file in markdown format.
//
// The changelog is prepended to the existing file content, so newer entries
// appear at the top. If the file does not exist, it will be created.
//
// The output format includes:
//   - A timestamped revision header
//   - Repository information in code blocks
//   - List of changelog entries
//
// Example output:
//
//	### New Revision (2026-02-09 20:30:00)
//
//	```repo
//	Repository: /path/to/repo
//	Ref: main
//	Date: 2026-02-09 18:45:23 +0100
//	```
//
//	- Fixed critical bug
//	- Added new feature
func (cl *Changelog) OutputTo(path string) error {
	cl.logger.Debug("Outputting changelog to file", "path", path)
	content := cl.formatBlock()
	return prepend(path, content)
}

// formatBlock generates the complete markdown-formatted changelog block.
// It combines the header, body, and a trailing newline.
func (cl *Changelog) formatBlock() string {
	var sb strings.Builder
	sb.WriteString(cl.header())
	sb.WriteString(cl.body())
	sb.WriteString("\n")
	return sb.String()
}

// header generates the timestamped revision header for the changelog.
// Format: "### New Revision (YYYY-MM-DD HH:MM:SS)"
func (cl *Changelog) header() string {
	timestamp := time.Now().Format(timestampFormat)
	return fmt.Sprintf("### New Revision (%s)\n\n", timestamp)
}

// body generates the main content of the changelog including repository
// information and changelog entries.
//
// Repository information is formatted in markdown code blocks.
// If no entries were added, it outputs "*no changes*".
func (cl *Changelog) body() string {
	var sb strings.Builder

	// repo infos
	for _, r := range cl.repos {
		sb.WriteString("```repo\n")
		sb.WriteString(fmt.Sprintf("Repository: %s\nRef: %s\nDate: %s\n", r.Repo, r.Ref, r.Date))
		sb.WriteString("```\n\n")
	}

	// normal entries
	if len(cl.entries) == 0 {
		sb.WriteString("*no changes*\n")
	} else {
		for _, e := range cl.entries {
			sb.WriteString("- " + e + "\n")
		}
	}

	return sb.String()
}

// prepend adds content to the beginning of a file.
//
// If the file does not exist, it will be created with the given content.
// If the file exists, the content is prepended while preserving existing content.
//
// The file is created with permissions 0644 (readable by all, writable by owner).
func prepend(path, content string) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	final := content + "\n" + string(old)
	return os.WriteFile(path, []byte(final), 0644)
}

// Close releases any resources held by the Changelog.
//
// It should be called when the Changelog is no longer needed,
// typically via defer immediately after creation.
//
// Example:
//
//	cl := changelog.NewChangelog(logger)
//	defer cl.Close()
func (cl *Changelog) Close() error {
	if closer, ok := cl.git.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

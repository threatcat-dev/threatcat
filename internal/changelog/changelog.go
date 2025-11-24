package changelog

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"
)

const timestampFormat = "2006-01-02 15:04:05"

type Changelog struct {
	entries []string     // free-form changelog messages
	repos   []CommitInfo // collected repo commit info
	logger  *slog.Logger
	git     GitRunner
	noGit   bool
}

type CommitInfo struct {
	Repo string
	Ref  string
	Date string
}

// NewChangelog creates a new Changelog instance
func NewChangelog(logger *slog.Logger) *Changelog {
	return &Changelog{
		entries: []string{},
		repos:   []CommitInfo{},
		logger:  logger.With("package", "changelog"),
		git:     realGitRunner{},
	}
}

// AddEntry adds a free-form message entry
func (cl *Changelog) AddEntry(msg string) {
	cl.entries = append(cl.entries, msg)
	cl.logger.Debug("An entry has been added to the changelog", "msg", msg)
}

// AddCommitInfo extracts repo info from files and adds it to repo slice
func (cl *Changelog) AddCommitInfo(file string) error {
	_, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("file not found: %s", file)
	}

	repo, err := cl.git.RepoRoot(file)
	if err != nil {
		if !errors.Is(err, ErrGitNotFound) {
			cl.logger.Info("Unable to determine git repo for file. Changelog will not contain repo info.", "file", file, "err", err)
		} else if !cl.noGit {
			cl.logger.Warn("Failed to find git executable. Changelog will not contain repo info.")
			cl.noGit = true
		}
		return nil
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

// OutputTo writes the changelog entries to a file (prepended)
func (cl *Changelog) OutputTo(path string) error {
	cl.logger.Debug("Outputting changelog to file", "path", path)
	content := cl.formatBlock()
	return prepend(path, content)
}

func (cl *Changelog) formatBlock() string {
	var sb strings.Builder
	sb.WriteString(cl.header())
	sb.WriteString(cl.body())
	sb.WriteString("\n")
	return sb.String()
}

func (cl *Changelog) header() string {
	timestamp := time.Now().Format(timestampFormat)
	return fmt.Sprintf("### New Revision (%s)\n\n", timestamp)
}

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

// prepend prepends the given string to the file
func prepend(path, content string) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	final := content + "\n" + string(old)
	return os.WriteFile(path, []byte(final), 0644)
}

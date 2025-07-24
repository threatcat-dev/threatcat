package changelog

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

const timestampFormat = "2006-01-02 15:04:05"

type changelog struct {
	entries []string
	logger  *slog.Logger
}

// NewChangelog creates a new Changelog instance
func NewChangelog(logger *slog.Logger) *changelog {
	return &changelog{
		entries: []string{},
		logger:  logger.With("package", "changelog"),
	}
}

// AddEntry adds an entry to the changelog
func (cl *changelog) AddEntry(msg string) {
	cl.entries = append(cl.entries, msg)
	cl.logger.Debug("An entry has been added to the changelog", "msg", msg)
}

// OutputTo outputs the changelog to a given filepath.
// In its current implementation, the content is
func (cl *changelog) OutputTo(path string) error {
	cl.logger.Debug("Outputting changelog to file", "path", path)
	content := cl.formatBlock()
	return prepend(path, content)
}

// formatBlock pretty-prints th list of entries in a specific format
// to be appended/prepended to the changelog file.
func (cl *changelog) formatBlock() string {
	var sb strings.Builder
	sb.WriteString(cl.header())
	sb.WriteString(cl.body())
	sb.WriteString("\n")
	return sb.String()
}

// header can be expanded at a later time to include
// more information than just the timestamp.
func (cl *changelog) header() string {
	timestamp := time.Now().Format(timestampFormat)
	return fmt.Sprintf("### New Revision (%s)\n", timestamp)
}

// body prints the changelog entries as a markdown list,
// or "no changes" if the list is empty.
func (cl *changelog) body() string {
	if len(cl.entries) == 0 {
		return "*no changes*"
	}

	var sb strings.Builder
	for _, entry := range cl.entries {
		sb.WriteString("- " + entry + "\n")
	}

	return sb.String()
}

// prepend prepends the given string to the file
func prepend(path, content string) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	final := content + string(old)
	return os.WriteFile(path, []byte(final), 0644)
}

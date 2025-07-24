package changelog

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddEntryAndFormatBlock(t *testing.T) {
	cl := NewChangelog(slog.Default())
	cl.AddEntry("Initial commit")
	cl.AddEntry("Added feature X")

	output := cl.formatBlock()

	assert.Contains(t, output, "### New Revision (")
	assert.Contains(t, output, "- Initial commit")
	assert.Contains(t, output, "- Added feature X")
}

func TestBodyEmpty(t *testing.T) {
	cl := NewChangelog(slog.Default())

	body := cl.body()
	assert.Equal(t, "*no changes*", body)
}

func TestOutputTo_CreatesOrPrependsFile(t *testing.T) {
	cl := NewChangelog(slog.Default())
	cl.AddEntry("First change")

	tmpFile := "test_changelog.md"
	t.Cleanup(func() { _ = os.Remove(tmpFile) })

	// Write first changelog
	err := cl.OutputTo(tmpFile)
	require.NoError(t, err)

	content1, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(content1), "First change")

	// Write second changelog (should prepend)
	cl2 := NewChangelog(slog.Default())
	cl2.AddEntry("Second change")
	err = cl2.OutputTo(tmpFile)
	require.NoError(t, err)

	content2, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// New entry should be at the top
	assert.True(t, strings.HasPrefix(string(content2), cl2.formatBlock()))
	// Old entry should still be present
	assert.Contains(t, string(content2), string(content1))
}

package changelog

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	assert.Equal(t, "*no changes*\n", body)
}

func TestOutputTo_CreatesOrPrependsFile(t *testing.T) {
	cl := NewChangelog(slog.Default())
	cl.AddEntry("First change")

	tmpFile := "test_changelog.md"
	t.Cleanup(func() { _ = os.Remove(tmpFile) })

	// Write first changelog
	require.NoError(t, cl.OutputTo(tmpFile))

	content1, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(content1), "First change")

	// Write second changelog (should prepend)
	cl2 := NewChangelog(slog.Default())
	cl2.AddEntry("Second change")
	require.NoError(t, cl2.OutputTo(tmpFile))

	content2, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	// New entry should be at the top
	assert.True(t, strings.HasPrefix(string(content2), cl2.formatBlock()))
	// Old entry should still be present
	assert.Contains(t, string(content2), string(content1))
}

// --- Mocks ---
type mockGitRunner struct {
	repoRootFunc   func(file string) (string, error)
	commitInfoFunc func(repo string) (CommitInfo, error)
}

func (m mockGitRunner) RepoRoot(file string) (string, error) {
	return m.repoRootFunc(file)
}

func (m mockGitRunner) CommitInfo(repo string) (CommitInfo, error) {
	return m.commitInfoFunc(repo)
}

func newTestChangelog(gr GitRunner) *Changelog {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cl := NewChangelog(logger)
	cl.git = gr
	return cl
}

func writeTempFile(t *testing.T, name string) string {
	t.Helper()
	tmp := filepath.Join(os.TempDir(), name)
	require.NoError(t, os.WriteFile(tmp, []byte("dummy"), 0644))
	return tmp
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestMain(m *testing.M) {
	files, _ := filepath.Glob("testoutput_*")
	for _, f := range files {
		_ = os.Remove(f)
	}
	os.Exit(m.Run())
}

// --- Git Tests ---
func TestGitNotInstalled(t *testing.T) {
	file := writeTempFile(t, "f.go")
	cl := newTestChangelog(mockGitRunner{
		repoRootFunc: func(string) (string, error) {
			return "", ErrGitNotFound
		},
		commitInfoFunc: func(string) (CommitInfo, error) {
			return CommitInfo{}, ErrGitNotFound
		},
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	err := cl.AddCommitInfo(file)

	// expecting to fail gracefully
	assert.NoError(t, err)
}

func TestGitReturnsGibberish(t *testing.T) {
	file := writeTempFile(t, "f.go")
	cl := newTestChangelog(mockGitRunner{
		repoRootFunc: func(string) (string, error) { return "/fake/repo", nil },
		commitInfoFunc: func(string) (CommitInfo, error) {
			return CommitInfo{}, errors.New("unexpected git log output")
		},
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	err := cl.AddCommitInfo(file)

	// expecting to fail gracefully
	assert.NoError(t, err)
}

// --- Adding Files ---
func TestAddSingleFile(t *testing.T) {
	file := writeTempFile(t, "f1.go")
	cl := newTestChangelog(mockGitRunner{
		repoRootFunc: func(string) (string, error) { return "/repo1", nil },
		commitInfoFunc: func(string) (CommitInfo, error) {
			return CommitInfo{Repo: "/repo1", Ref: "main", Date: time.Now().Format(time.RFC3339)}, nil
		},
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	require.NoError(t, cl.AddCommitInfo(file))

	out := "testoutput_single.md"
	require.NoError(t, cl.OutputTo(out))
	t.Log("\n" + readFile(t, out))
}

func TestAddMultipleFilesMultipleRepos(t *testing.T) {
	f1 := writeTempFile(t, "f1.go")
	f2 := writeTempFile(t, "f2.go")

	cl := newTestChangelog(mockGitRunner{
		repoRootFunc: func(file string) (string, error) {
			if file == f1 {
				return "/repo1", nil
			}
			return "/repo2", nil
		},
		commitInfoFunc: func(repo string) (CommitInfo, error) {
			return CommitInfo{Repo: repo, Ref: "main", Date: time.Now().Format(time.RFC3339)}, nil
		},
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	require.NoError(t, cl.AddCommitInfo(f1))
	require.NoError(t, cl.AddCommitInfo(f2))

	out := "testoutput_multirepo.md"
	require.NoError(t, cl.OutputTo(out))
	t.Log("\n" + readFile(t, out))
}

func TestAddMultipleFilesSameRepo(t *testing.T) {
	f1 := writeTempFile(t, "f1.go")
	f2 := writeTempFile(t, "f2.go")

	cl := newTestChangelog(mockGitRunner{
		repoRootFunc: func(string) (string, error) { return "/repo1", nil },
		commitInfoFunc: func(repo string) (CommitInfo, error) {
			return CommitInfo{Repo: repo, Ref: "main", Date: time.Now().Format(time.RFC3339)}, nil
		},
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	require.NoError(t, cl.AddCommitInfo(f1))
	require.NoError(t, cl.AddCommitInfo(f2))

	require.Len(t, cl.repos, 1, "expected only one repo to be tracked")

	out := "testoutput_samerepo.md"
	require.NoError(t, cl.OutputTo(out))
	t.Log("\n" + readFile(t, out))
}

func TestNoFilesAdded(t *testing.T) {
	cl := newTestChangelog(mockGitRunner{
		repoRootFunc:   func(string) (string, error) { return "", nil },
		commitInfoFunc: func(string) (CommitInfo, error) { return CommitInfo{}, nil },
	})

	cl.AddEntry("Example Entry 1")
	cl.AddEntry("Example Entry 2")

	out := "testoutput_nofiles.md"
	require.NoError(t, cl.OutputTo(out))
	t.Log("\n" + readFile(t, out))
}

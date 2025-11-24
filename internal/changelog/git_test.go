package changelog

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// helper to run git commands inside a directory
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\nOutput: %s", args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func initTestRepo(t *testing.T) string {
	dir := t.TempDir()

	// init repo
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.name", "Test User")
	runGit(t, dir, "config", "user.email", "test@example.com")

	// add a file
	f := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(f, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	runGit(t, dir, "add", "hello.txt")
	runGit(t, dir, "commit", "-m", "initial commit")

	return f
}

func TestRealGitRunner_RepoRootAndCommitInfo(t *testing.T) {
	file := initTestRepo(t)
	repo := filepath.Dir(file) // file lives in repo root

	gr := realGitRunner{}

	root, err := gr.RepoRoot(file)
	if err != nil {
		t.Fatalf("RepoRoot failed: %v", err)
	}
	if filepath.Clean(root) != filepath.Clean(repo) {
		t.Errorf("expected repo root %s, got %s", repo, root)
	}

	ci, err := gr.CommitInfo(root)
	if err != nil {
		t.Fatalf("CommitInfo failed: %v", err)
	}
	if ci.Repo != root {
		t.Errorf("expected ci.Repo=%s, got %s", root, ci.Repo)
	}
	if ci.Ref == "" {
		t.Error("expected non-empty Ref")
	}
	if _, err := time.Parse("2006-01-02 15:04:05 -0700", ci.Date); err != nil {
		t.Errorf("expected valid git commit date, got %q, parse error: %v", ci.Date, err)
	}
}

func TestChangelogWithRealGitRunner(t *testing.T) {
	file := initTestRepo(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cl := NewChangelog(logger)

	// Replace with realGitRunner (default anyway, but being explicit)
	cl.git = realGitRunner{}

	if err := cl.AddCommitInfo(file); err != nil {
		t.Fatalf("AddCommitInfo failed: %v", err)
	}

	out := filepath.Join(t.TempDir(), "testoutput_integration.md")
	if err := cl.OutputTo(out); err != nil {
		t.Fatalf("OutputTo failed: %v", err)
	}

	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Repository:") {
		t.Errorf("expected output to contain Repository info, got:\n%s", content)
	}
	if !strings.Contains(string(content), "-") && !strings.Contains(string(content), "*no changes*") {
		t.Errorf("expected output to contain changelog body, got:\n%s", content)
	}
}

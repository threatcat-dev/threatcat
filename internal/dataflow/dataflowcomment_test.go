package dataflow

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/threatcat-dev/threatcat/internal/common"
)

func TestReadDockerCompose(t *testing.T) {
	dockeryaml := make([]string, 2)
	dockeryaml[0] = "testdata/docker-compose-for-test.yml"
	dockeryaml[1] = "testdata/docker-compose-for-test.yml"
	threatModel, err := ParseAndConvert(dockeryaml, make([]common.ThreatModel, 0), slog.Default())
	assert.Nil(t, err)
	assert.NotNil(t, threatModel)

	dockeryaml[1] = "testdata/unknonwn.yml"
	threatModel, err = ParseAndConvert(dockeryaml, make([]common.ThreatModel, 0), slog.Default())
	assert.NotNil(t, err)
	assert.Nil(t, threatModel)

}

func TestExtractAssetsArrow(t *testing.T) {
	a1, arrow, a2, ok := extractAssetsArrow("(web)-->(db)")
	assert.True(t, ok)
	assert.Equal(t, "web", a1)
	assert.Equal(t, "-->", arrow)
	assert.Equal(t, "db", a2)

	a1, arrow, a2, ok = extractAssetsArrow("(web)<-->(db2)")
	assert.True(t, ok)
	assert.Equal(t, "<-->", arrow)
	assert.Equal(t, "web", a1)
	assert.Equal(t, "db2", a2)

	_, _, _, ok = extractAssetsArrow("no parentheses")
	assert.False(t, ok)
}

func TestParseSingleDataFlow(t *testing.T) {
	an := &DataflowCommentParser{logger: slog.Default()}

	line := "#(web)-->(db);Flow1;http;Unencrypted;Public"

	df, ok := an.parseSingleDataFlow(line)
	assert.True(t, ok)
	assert.Equal(t, "web", df.Source)
	assert.Equal(t, "db", df.Target)
	assert.Equal(t, false, df.Bidirectional)
	assert.Equal(t, "Flow1", df.Name)
	assert.Equal(t, "http", df.Protocol)
	assert.False(t, df.Encrypted)
	assert.True(t, df.PublicNetwork)
}

func TestParseSingleDataFlowMalformed(t *testing.T) {
	an := &DataflowCommentParser{logger: slog.Default()}

	// Missing "#("
	_, ok := an.parseSingleDataFlow("(web)-->(db)")
	assert.False(t, ok)

	// Bad asset syntax
	_, ok = an.parseSingleDataFlow("#(web)--db")
	assert.False(t, ok)
}

func TestParseMeta(t *testing.T) {
	an := &DataflowCommentParser{logger: slog.Default()}
	var df common.DataFlow

	an.parseMeta([]string{"Flow1", "http", "Encrypted", "Public"}, &df)
	assert.Equal(t, "Flow1", df.Name)
	assert.Equal(t, "http", df.Protocol)
	assert.True(t, df.Encrypted)
	assert.True(t, df.PublicNetwork)

	// Unexpected encryption & public fields
	an.parseMeta([]string{"Name", "https", "wrong", "wrong"}, &df)
	assert.Equal(t, "Name", df.Name)
	assert.Equal(t, "https", df.Protocol)
	assert.False(t, df.Encrypted)
	assert.False(t, df.PublicNetwork)

	// Too few fields resets defaults
	an.parseMeta([]string{"Name"}, &df)
	assert.Equal(t, "", df.Name)
	assert.Equal(t, "", df.Protocol)
	assert.False(t, df.Encrypted)
	assert.False(t, df.PublicNetwork)
}

func TestReadComments(t *testing.T) {
	tmp := t.TempDir()
	fpath := filepath.Join(tmp, "test.yml")

	content := `services:
  web:
    image: nginx
    # (web)-->(db);Flow1;http;Unencrypted;Public
    # some other comment
db:
    image: postgres
`
	err := os.WriteFile(fpath, []byte(content), 0600)
	assert.NoError(t, err)

	an := &DataflowCommentParser{filePath: fpath, logger: slog.Default()}

	lines, err := an.readComments(fpath)
	assert.NoError(t, err)
	assert.Len(t, lines, 2)

	assert.Contains(t, lines[0], "# (web)-->(db);Flow1;http;Unencrypted;Public")
	assert.Contains(t, lines[1], "# some other comment")
}

func TestParseDataFlowsFromTestFile(t *testing.T) {

	path := filepath.Join("..", "dockercompose", "testdata", "docker-compose-for-test.yml") //Added relative path

	an := &DataflowCommentParser{
		filePath: path,
		logger:   slog.Default(),
	}

	dataflows, err := an.parseDataFlows()
	assert.NoError(t, err)
	assert.Len(t, dataflows, 4)
	// ---- FLOW 1 ----
	f := dataflows[0]
	assert.Equal(t, "web", f.Source)
	assert.Equal(t, "db", f.Target)
	assert.Equal(t, "Flow1", f.Name)
	assert.Equal(t, "http", f.Protocol)
	assert.False(t, f.Encrypted)
	assert.True(t, f.PublicNetwork)
	assert.Equal(t, false, f.Bidirectional)

	// ---- FLOW 2 ----
	f = dataflows[1]
	assert.Equal(t, "web", f.Source)
	assert.Equal(t, "db2", f.Target)
	assert.Equal(t, "Flow12", f.Name)
	assert.Equal(t, "https", f.Protocol)
	assert.True(t, f.Encrypted)
	assert.False(t, f.PublicNetwork)
	assert.Equal(t, true, f.Bidirectional)

	// ---- FLOW 3 ----
	f = dataflows[2]
	assert.Equal(t, "db", f.Source)
	assert.Equal(t, "db2", f.Target)
	assert.Equal(t, "Flow13", f.Name)
	assert.Equal(t, "https", f.Protocol)
	assert.True(t, f.Encrypted)
	assert.False(t, f.PublicNetwork)
	assert.Equal(t, true, f.Bidirectional)
	// ---- FLOW 4 ----
	f = dataflows[3]
	assert.Equal(t, "actor1", f.Source)
	assert.Equal(t, "web", f.Target)
	assert.Equal(t, "Dangling Dataflow", f.Name)
	assert.Equal(t, "Https", f.Protocol)
	assert.True(t, f.Encrypted)
	assert.False(t, f.PublicNetwork)
	assert.Equal(t, false, f.Bidirectional)
}

func TestParseAndConvertFromTestFile(t *testing.T) {

	path := filepath.Join("..", "dockercompose", "testdata", "docker-compose-for-test.yml") //Added relative path
	paths := []string{path, path}
	tModel, err := ParseAndConvert(paths, make([]common.ThreatModel, 0), slog.Default())
	assert.NoError(t, err)
	dataflows := tModel.DataFlows

	assert.Len(t, dataflows, 8)
	// ---- FLOW 1 ----
	f := dataflows[0]
	assert.Equal(t, "web", f.Source)
	assert.Equal(t, "db", f.Target)
	assert.Equal(t, "Flow1", f.Name)
	assert.Equal(t, "http", f.Protocol)
	assert.False(t, f.Encrypted)
	assert.True(t, f.PublicNetwork)
	assert.Equal(t, false, f.Bidirectional)

	// ---- FLOW 2 ----
	f = dataflows[1]
	assert.Equal(t, "web", f.Source)
	assert.Equal(t, "db2", f.Target)
	assert.Equal(t, "Flow12", f.Name)
	assert.Equal(t, "https", f.Protocol)
	assert.True(t, f.Encrypted)
	assert.False(t, f.PublicNetwork)
	assert.Equal(t, true, f.Bidirectional)

	// ---- FLOW 3 ----
	f = dataflows[2]
	assert.Equal(t, "db", f.Source)
	assert.Equal(t, "db2", f.Target)
	assert.Equal(t, "Flow13", f.Name)
	assert.Equal(t, "https", f.Protocol)
	assert.True(t, f.Encrypted)
	assert.False(t, f.PublicNetwork)
	assert.Equal(t, true, f.Bidirectional)
}

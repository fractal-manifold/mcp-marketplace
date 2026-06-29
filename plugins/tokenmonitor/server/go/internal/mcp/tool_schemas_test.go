package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/config"
	"github.com/fractal-manifold/tokenmonitor-mcp/internal/state"
)

// findToolSchemas walks up from the test working directory to compat/
// tool-schemas.json. Unlike the byte-exact vector tests, this golden is
// also vendored into the server/compat/ runtime slice (py/js load it at
// runtime), so the nearest copy up-tree — server/compat/tool-schemas.json
// — is the authoritative one for this runtime. Skips on a standalone
// checkout that ships neither copy.
func findToolSchemas(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 9; i++ {
		candidate := filepath.Join(dir, "compat", "tool-schemas.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skipf("compat/tool-schemas.json not found upward from %s (standalone checkout)", wd)
	return ""
}

// goldenTool is the shape we pull out of tool-schemas.json for comparison.
type goldenTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	} `json:"inputSchema"`
}

// marshalledTool mirrors goldenTool but is filled by marshalling the
// registered mcp.Tool to JSON — exactly the bytes the MCP client sees.
type marshalledTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	} `json:"inputSchema"`
}

// TestToolSchemas_MatchGolden asserts that every tool the Go MCP server
// registers carries byte-identical name, description and per-parameter
// descriptions to compat/tool-schemas.json — the cross-runtime contract
// the py/js brokers load verbatim. Go hardcodes its descriptions in
// source, so this test is what keeps the three runtimes from drifting
// (e.g. when the manifest signer path or service.toml→tokenmonitor.toml rename
// lands in the golden).
func TestToolSchemas_MatchGolden(t *testing.T) {
	path := findToolSchemas(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Tools []goldenTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse tool-schemas.json: %v", err)
	}
	if len(doc.Tools) == 0 {
		t.Fatal("golden tools empty")
	}
	golden := make(map[string]goldenTool, len(doc.Tools))
	for _, g := range doc.Tools {
		golden[g.Name] = g
	}

	srv := NewServer(Deps{
		Cfg:     &config.Config{},
		State:   state.New(),
		Logs:    nil,
		Version: "test",
	})

	registered := srv.ListTools()
	if len(registered) != len(doc.Tools) {
		t.Errorf("tool count: registered %d, golden %d", len(registered), len(doc.Tools))
	}

	for name, st := range registered {
		g, ok := golden[name]
		if !ok {
			t.Errorf("registered tool %q has no golden entry in tool-schemas.json", name)
			continue
		}
		// Marshal the Tool to its wire JSON and re-decode the slice we care
		// about, so the comparison is against exactly what the client sees.
		blob, err := json.Marshal(st.Tool)
		if err != nil {
			t.Fatalf("marshal tool %q: %v", name, err)
		}
		var got marshalledTool
		if err := json.Unmarshal(blob, &got); err != nil {
			t.Fatalf("unmarshal tool %q: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			if got.Description != g.Description {
				t.Errorf("description drift for %q:\n  got    %q\n  golden %q", name, got.Description, g.Description)
			}
			for param, gp := range g.InputSchema.Properties {
				gotp, ok := got.InputSchema.Properties[param]
				if !ok {
					t.Errorf("%q: golden param %q missing from registered tool", name, param)
					continue
				}
				if gotp.Description != gp.Description {
					t.Errorf("param %q.%q description drift:\n  got    %q\n  golden %q", name, param, gotp.Description, gp.Description)
				}
			}
			// Flag params the Go tool declares that the golden doesn't know.
			for param := range got.InputSchema.Properties {
				if _, ok := g.InputSchema.Properties[param]; !ok {
					t.Errorf("%q: registered param %q not present in golden", name, param)
				}
			}
		})
	}

	// Flag golden tools that aren't registered at all.
	for name := range golden {
		if _, ok := registered[name]; !ok {
			t.Errorf("golden tool %q is not registered by the Go server", name)
		}
	}
}

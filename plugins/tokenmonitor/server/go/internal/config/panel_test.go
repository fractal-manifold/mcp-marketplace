package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadTOML(t *testing.T, body string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tokenmonitor.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

const authHeader = "[auth]\npsk_passphrase = \"passphrase-1234\"\n"

func TestPanelFileBareString(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel]
file = "~/panel.json"
`)
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, "panel.json")
	if got := cfg.PanelFileDefault(); got != want {
		t.Errorf("bare file string should become the default: got %q want %q", got, want)
	}
	if got := cfg.PanelFileExplicit("dev1"); got != "" {
		t.Errorf("no explicit per-device entry expected, got %q", got)
	}
}

func TestPanelFileTable(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel.file]
default = "/panels/default.json"
"tmon-ab12" = "/panels/ab12.json"
`)
	if got := cfg.PanelFileDefault(); got != "/panels/default.json" {
		t.Errorf("default entry: got %q", got)
	}
	if got := cfg.PanelFileExplicit("tmon-ab12"); got != "/panels/ab12.json" {
		t.Errorf("explicit entry: got %q", got)
	}
	if got := cfg.PanelFileExplicit("other"); got != "" {
		t.Errorf("unknown device: got %q want empty", got)
	}
}

func TestPanelCommandTable(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel.command]
default = ["python3", "~/bin/gen.py"]
"tmon-ab12" = ["/usr/bin/special", "--fast"]
`)
	cmds := cfg.PanelCommandMap()
	home, _ := os.UserHomeDir()
	wantDefault := filepath.Join(home, "bin/gen.py")
	if got := cmds["default"]; len(got) != 2 || got[0] != "python3" || got[1] != wantDefault {
		t.Errorf("default command (argv[1] tilde-expanded): got %v", got)
	}
	if got := cmds["tmon-ab12"]; len(got) != 2 || got[0] != "/usr/bin/special" || got[1] != "--fast" {
		t.Errorf("per-device command: got %v", got)
	}
}

func TestPanelUnconfigured(t *testing.T) {
	cfg := loadTOML(t, authHeader)
	if cfg.PanelCommandMap() != nil {
		t.Errorf("no [panel.command] should yield nil map, got %v", cfg.PanelCommandMap())
	}
	if cfg.PanelFileDefault() != "" || cfg.PanelDir() != "" {
		t.Errorf("no [panel] should yield empty file/dir")
	}
}

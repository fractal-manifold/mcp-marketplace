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

func TestPanelCommandIntervalBareNumber(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel]
command_interval_s = 900
`)
	if got := cfg.PanelCommandIntervalFor("anything"); got != 900 {
		t.Errorf("bare number should become the default entry: got %d", got)
	}
}

func TestPanelCommandIntervalTable(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel.command_interval_s]
default = 900
"tmon-ab12" = 60
`)
	if got := cfg.PanelCommandIntervalFor("tmon-ab12"); got != 60 {
		t.Errorf("explicit device interval: got %d", got)
	}
	if got := cfg.PanelCommandIntervalFor("other"); got != 900 {
		t.Errorf("unknown device falls back to default: got %d", got)
	}
}

func TestPanelCommandIntervalAbsentIsZero(t *testing.T) {
	cfg := loadTOML(t, authHeader+`
[panel.command]
default = ["gen"]
`)
	if got := cfg.PanelCommandIntervalFor("dev1"); got != 0 {
		t.Errorf("absent interval must be 0 (long-lived process), got %d", got)
	}
}

// A bad interval must fail loudly rather than silently disabling pacing — and
// identically in the py/js brokers, which validate the same three cases.
func TestPanelCommandIntervalRejectsBadValues(t *testing.T) {
	for name, body := range map[string]string{
		"negative": "[panel]\ncommand_interval_s = -5\n",
		// 0.5 s truncated to 0 would mean "long-lived process" — the opposite
		// contract to what was asked for, so it is an error, not a rounding.
		"fractional": "[panel]\ncommand_interval_s = 0.5\n",
		"string":     "[panel]\ncommand_interval_s = \"900\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "tokenmonitor.toml")
			if err := os.WriteFile(p, []byte(authHeader+body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(p); err == nil {
				t.Errorf("%s interval must be rejected at load", name)
			}
		})
	}
}

// A float that IS a whole number is fine — `900.0` is just how some editors
// (and some TOML writers) spell 900.
func TestPanelCommandIntervalAcceptsIntegralFloat(t *testing.T) {
	cfg := loadTOML(t, authHeader+"[panel]\ncommand_interval_s = 900.0\n")
	if got := cfg.PanelCommandIntervalFor("dev1"); got != 900 {
		t.Errorf("900.0 should parse as 900, got %d", got)
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

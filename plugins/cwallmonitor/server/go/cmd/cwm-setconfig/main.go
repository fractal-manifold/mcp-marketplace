// cwm-setconfig — DEV-ONLY helper to stage a CONFIG pending (theme / autorotate)
// directly via the registry package, the same way wall_monitor_set_device_pending
// would (same merge + version bump + flock). Useful when the MCP server isn't
// wired into the calling session. Only the flags that are explicitly passed are
// applied; everything else (broker_url, psk, city, providers, firmware fields)
// is preserved from the device's current active/pending payload by the merge.
// Throwaway dev tool.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fractal-manifold/cwm-mcp/internal/registry"
)

func main() {
	def := ""
	if home, err := os.UserHomeDir(); err == nil {
		def = filepath.Join(home, ".config", "claude-wall-monitor", "devices")
	}
	dir := flag.String("dir", def, "devices dir")
	id := flag.String("id", "", "device id")
	theme := flag.String("theme", "", "theme_mode: day|night|auto (empty = no change)")
	rotS := flag.Int("rotate-s", 0, "autorotate_interval_s 1..300 (0 = no change)")
	rotEn := flag.String("rotate-enabled", "", "autorotate_enabled: true|false (empty = no change)")
	flag.Parse()

	if *id == "" {
		fmt.Fprintln(os.Stderr, "usage: cwm-setconfig -id <id> [-theme day|night|auto] [-rotate-s 1..300] [-rotate-enabled true|false] [-dir <devices>]")
		os.Exit(2)
	}

	var upd registry.ConfigPayload
	if *theme != "" {
		if *theme != "day" && *theme != "night" && *theme != "auto" {
			fmt.Fprintln(os.Stderr, "theme must be day|night|auto")
			os.Exit(2)
		}
		upd.ThemeMode = *theme
	}
	if *rotS != 0 {
		if *rotS < 1 || *rotS > 300 {
			fmt.Fprintln(os.Stderr, "rotate-s must be 1..300")
			os.Exit(2)
		}
		v := uint16(*rotS)
		upd.AutorotateIntervalS = &v
	}
	if *rotEn != "" {
		if *rotEn != "true" && *rotEn != "false" {
			fmt.Fprintln(os.Stderr, "rotate-enabled must be true|false")
			os.Exit(2)
		}
		b := *rotEn == "true"
		upd.AutorotateEnabled = &b
	}

	reg, err := registry.New(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry.New:", err)
		os.Exit(1)
	}
	dev, err := reg.SetPending(*id, upd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SetPending:", err)
		os.Exit(1)
	}
	if dev.Pending == nil {
		fmt.Println("no pending written (payload equals active)")
		return
	}
	p := dev.Pending
	rot := "(unchanged)"
	if p.AutorotateIntervalS != nil {
		rot = fmt.Sprintf("%ds", *p.AutorotateIntervalS)
	}
	en := "(unchanged)"
	if p.AutorotateEnabled != nil {
		en = fmt.Sprintf("%t", *p.AutorotateEnabled)
	}
	fmt.Printf("pending v%d staged: theme=%q rotate_enabled=%s rotate_interval=%s\n",
		p.Version, p.ThemeMode, en, rot)
}

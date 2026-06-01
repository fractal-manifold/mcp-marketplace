// cwm-setpending — DEV-ONLY helper to stage an OTA pending directly via the
// registry package, bypassing the MCP tool's HTTPS-only URL guard so a
// locally-built .bin can be served over plain HTTP from the broker's own
// /firmware/ endpoint on the LAN. Mirrors exactly what
// wall_monitor_set_device_pending does (same merge + version bump + flock),
// only the scheme check is skipped. Throwaway; remove after the demo.
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
	url := flag.String("url", "", "firmware_url")
	sha := flag.String("sha", "", "firmware_sha256 (64 hex)")
	ver := flag.String("ver", "", "firmware_version")
	flag.Parse()

	if *id == "" || *url == "" || *sha == "" || *ver == "" {
		fmt.Fprintln(os.Stderr, "usage: cwm-setpending -id <id> -url <url> -sha <hex> -ver <semver> [-dir <devices>]")
		os.Exit(2)
	}

	reg, err := registry.New(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry.New:", err)
		os.Exit(1)
	}
	dev, err := reg.SetPending(*id, registry.ConfigPayload{
		FirmwareURL:     *url,
		FirmwareSHA256:  *sha,
		FirmwareVersion: *ver,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "SetPending:", err)
		os.Exit(1)
	}
	if dev.Pending == nil {
		fmt.Println("no pending written (payload equals active)")
		return
	}
	fmt.Printf("pending v%d staged: url=%s ver=%s\n", dev.Pending.Version, dev.Pending.FirmwareURL, dev.Pending.FirmwareVersion)
}

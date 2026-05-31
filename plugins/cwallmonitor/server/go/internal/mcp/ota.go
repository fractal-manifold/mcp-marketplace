package mcp

import (
	"context"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/fractal-manifold/cwm-mcp/internal/ota"
)

// handleCheckUpdates forces an OTA-channel check now and reports (or
// stages) what the background loop would do. Works from any process — it
// only needs the config + registry, both in Deps — so a follower session
// can preview updates even when a different process owns the broker.
func handleCheckUpdates(d Deps) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if d.Registry == nil {
			return registryUnavailable(), nil
		}
		dryRun := req.GetBool("dry_run", true)
		sku := strings.ToUpper(strings.TrimSpace(req.GetString("sku", "")))
		deviceID := strings.ToLower(strings.TrimSpace(req.GetString("device_id", "")))

		checker := ota.NewChecker(d.Cfg, d.Registry, nil)
		rep, err := checker.Check(ctx, dryRun, sku, deviceID)
		if err != nil {
			return mcp.NewToolResultErrorFromErr("check_updates", err), nil
		}
		return mcp.NewToolResultJSON(rep)
	}
}

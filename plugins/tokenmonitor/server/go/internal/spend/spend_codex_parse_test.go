package spend

import (
	"os"
	"path/filepath"
	"testing"
)

// A codex rollout log exercising three parser edge cases (bug 19):
//   - a malformed session_meta (a string, not an object) must not crash;
//   - a nested payload token_count is counted;
//   - a TOP-LEVEL token_count (no payload wrapper) is ignored — only the
//     nested one drives the totals (Go reference semantics).
//
// The top-level record is placed LAST so a "payload || o" fallback would let
// it win (999) — the correct parser keeps the nested totals (90 / 50).
const codexParseFixture = `{"type":"session_meta","session_meta":"bogus-string","timestamp":"2026-03-20T10:00:00Z"}
{"type":"event_msg","payload":{"type":"token_count","info":{"total_token_usage":{"input_tokens":100,"cached_input_tokens":10,"output_tokens":50}}}}
{"type":"token_count","info":{"total_token_usage":{"input_tokens":999,"output_tokens":999}}}
`

func TestCodexRecords_TopLevelTokenCountIgnoredAndBogusMetaSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rollout-test.jsonl")
	if err := os.WriteFile(path, []byte(codexParseFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	recs := codexRecords(path)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	// input = 100 - 10 cached = 90; output = 50; cacheRead = 10. If the
	// top-level token_count leaked in, these would be 999.
	if r.input != 90 || r.output != 50 || r.cacheRead != 10 {
		t.Fatalf("totals leaked top-level token_count: input=%d output=%d cacheRead=%d", r.input, r.output, r.cacheRead)
	}
}

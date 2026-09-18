// Package state holds the small piece of runtime state that the MCP tools
// need to introspect: am I the leader or a follower, when did the ESP32
// last hit me, what was the last response code, etc.
//
// Kept deliberately tiny — anything richer (per-IP histograms, latency
// percentiles, …) goes elsewhere. The broker and the leader-election
// loop both poke into the same *State via concurrent-safe setters.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/fractal-manifold/tokenmonitor-mcp/internal/sessionlife"
)

type Role int

const (
	RoleUnknown Role = iota
	RoleLeader
	RoleFollower
)

func (r Role) String() string {
	switch r {
	case RoleLeader:
		return "leader"
	case RoleFollower:
		return "follower"
	default:
		return "unknown"
	}
}

type State struct {
	mu                sync.RWMutex
	persistMu         sync.Mutex
	role              Role
	roleSince         time.Time
	lastRequestAt     time.Time
	lastRequestRemote string
	lastRequestStatus int
	requestsTotal     uint64
	update            UpdateInfo
	shared            bool
}

// UpdateInfo is the cached result of the broker self-version check: is a newer
// broker/plugin release published than the one running. Known is false until
// the first successful fetch of the remote marketplace catalog; while unknown
// the broker advertises nothing (never a false "up to date" or "outdated").
type UpdateInfo struct {
	Known     bool      `json:"known"`
	Outdated  bool      `json:"outdated"`
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

func New() *State {
	return &State{role: RoleUnknown, roleSince: time.Now()}
}

// LastRequestAt reports when a device last hit the broker, zero if never.
// The mDNS publisher reads it to decide whether its advertisement has gone
// unheard and should be re-announced.
func (s *State) LastRequestAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRequestAt
}

// SetRole records a role transition. No-op if the role didn't change.
func (s *State) SetRole(r Role) {
	s.mu.Lock()
	if s.role == r {
		s.mu.Unlock()
		return
	}
	s.role = r
	s.roleSince = time.Now()
	shared := s.shared
	s.mu.Unlock()
	if shared {
		s.persist()
	}
}

// RecordRequest is called by the broker handler after each /credentials hit
// (regardless of whether auth passed — what matters is observed traffic).
func (s *State) RecordRequest(remote string, status int, t time.Time) {
	s.mu.Lock()
	s.lastRequestAt = t
	s.lastRequestRemote = remote
	s.lastRequestStatus = status
	s.requestsTotal++
	shared := s.shared
	s.mu.Unlock()
	if shared {
		s.persist()
	}
}

// SetUpdate records the latest broker self-version-check result. The
// update-check poller pokes this concurrently; the broker /sync handler and
// the MCP health/status tools read it back via Update.
func (s *State) SetUpdate(u UpdateInfo) {
	s.mu.Lock()
	s.update = u
	shared := s.shared
	s.mu.Unlock()
	if shared {
		s.persist()
	}
}

// Update returns the last cached self-version-check result (zero value =
// Known:false, i.e. no check has succeeded yet).
func (s *State) Update() UpdateInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.update
}

// Snapshot is an immutable view suitable for serializing back to MCP
// callers. Times are zero values if the event has never happened.
// The Runtime field identifies which language implementation produced
// this snapshot ("go" | "python" | "js"); it lets the launcher and
// users see which port answered without having to introspect $PATH.
type Snapshot struct {
	Runtime           string    `json:"runtime"`
	Role              string    `json:"role"`
	RoleSince         time.Time `json:"role_since"`
	LastRequestAt     time.Time `json:"last_request_at,omitempty"`
	LastRequestRemote string    `json:"last_request_remote,omitempty"`
	LastRequestStatus int       `json:"last_request_status,omitempty"`
	RequestsTotal     uint64    `json:"requests_total"`
	// UpdateAvailable is true when the self-version check found a newer
	// broker/plugin release than the one running. Omitted (absent) until the
	// first successful check, so callers can distinguish "up to date" from
	// "not yet checked".
	UpdateAvailable *bool  `json:"update_available,omitempty"`
	LatestVersion   string `json:"latest_version,omitempty"`
}

// Runtime is the identifier this implementation reports in the
// Snapshot. The Go impl is "go"; Python/JS ports must report their own
// values to keep tokenmonitor_status diagnosable end-to-end.
const Runtime = "go"

func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := Snapshot{
		Runtime:           Runtime,
		Role:              s.role.String(),
		RoleSince:         s.roleSince,
		LastRequestAt:     s.lastRequestAt,
		LastRequestRemote: s.lastRequestRemote,
		LastRequestStatus: s.lastRequestStatus,
		RequestsTotal:     s.requestsTotal,
	}
	if s.update.Known {
		avail := s.update.Outdated
		snap.UpdateAvailable = &avail
		snap.LatestVersion = s.update.Latest
	}
	return snap
}

// EnableShared makes this daemon's snapshot visible to the lightweight MCP
// adapters. It is explicit so state unit tests and follower adapters never
// write into the user's runtime directory.
func (s *State) EnableShared() {
	s.mu.Lock()
	s.shared = true
	s.mu.Unlock()
	s.persist()
}

func sharedPath() (string, error) {
	dir, err := sessionlife.RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "broker-state.json"), nil
}

func (s *State) persist() {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	path, err := sharedPath()
	if err != nil {
		return
	}
	b, err := json.Marshal(s.Snapshot())
	if err != nil {
		return
	}
	tmp := path + ".tmp-" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// LoadSharedSnapshot reads the daemon-owned snapshot atomically published on
// disk. Adapters fall back to their local state when the daemon has not yet
// produced one.
func LoadSharedSnapshot() (Snapshot, error) {
	path, err := sharedPath()
	if err != nil {
		return Snapshot{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return Snapshot{}, err
	}
	if snap.Role == "" {
		return Snapshot{}, errors.New("shared broker snapshot has no role")
	}
	return snap, nil
}

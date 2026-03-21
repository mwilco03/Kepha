package ops

import (
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/config"
)

// Revision is a simplified config revision for listing.
type Revision struct {
	RevNumber int    `json:"rev_number"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

// Commit creates a new config revision. The caller (daemon or CLI) is
// responsible for triggering the actual apply via the daemon.
func (o *Ops) Commit(actor Actor, message string) (int, error) {
	if message == "" {
		message = "manual commit"
	}
	rev, err := o.store.Commit(message)
	if err != nil {
		return 0, err
	}
	o.audit(actor, "commit", "config", fmt.Sprintf("%d", rev), map[string]string{"message": message})
	return rev, nil
}

// Rollback restores config to a previous revision. The caller is
// responsible for triggering the actual apply via the daemon.
func (o *Ops) Rollback(actor Actor, rev int) error {
	if err := o.store.Rollback(rev); err != nil {
		return err
	}
	o.audit(actor, "rollback", "config", fmt.Sprintf("%d", rev), nil)
	return nil
}

// ListRevisions returns all config revisions. Read-only.
func (o *Ops) ListRevisions() ([]Revision, error) {
	storeRevs, err := o.store.ListRevisions()
	if err != nil {
		return nil, err
	}
	revs := make([]Revision, len(storeRevs))
	for i, r := range storeRevs {
		revs[i] = Revision{RevNumber: r.RevNumber, Timestamp: r.Timestamp, Message: r.Message}
	}
	return revs, nil
}

// Diff returns two config snapshots for comparison. Read-only.
func (o *Ops) Diff(rev1, rev2 int) (*config.ConfigSnapshot, *config.ConfigSnapshot, error) {
	return o.store.Diff(rev1, rev2)
}

// Export returns the current config as a snapshot. Read-only.
func (o *Ops) Export() (*config.ConfigSnapshot, error) {
	return o.store.Export()
}

// Import replaces the current config with a snapshot.
func (o *Ops) Import(actor Actor, snap *config.ConfigSnapshot) error {
	if err := o.store.Import(snap); err != nil {
		return err
	}
	o.audit(actor, "import", "config", "", nil)
	return nil
}

// ListAuditLog returns recent audit entries. Read-only.
func (o *Ops) ListAuditLog(limit int) ([]config.AuditEntry, error) {
	return o.store.ListAuditLog(limit)
}

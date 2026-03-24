package service

import (
	"github.com/mwilco03/kepha/internal/ha"
)

// HAWrapper adapts ha.HAManager to satisfy the service.Service interface.
type HAWrapper struct {
	mgr *ha.HAManager
}

func NewHAWrapper() *HAWrapper {
	return &HAWrapper{mgr: ha.NewHAManager()}
}

func (w *HAWrapper) Name() string        { return w.mgr.Name() }
func (w *HAWrapper) DisplayName() string { return w.mgr.DisplayName() }
func (w *HAWrapper) Description() string { return w.mgr.Description() }
func (w *HAWrapper) Category() string    { return w.mgr.Category() }
func (w *HAWrapper) Dependencies() []string { return w.mgr.Dependencies() }

func (w *HAWrapper) Start(cfg map[string]string) error { return w.mgr.Start(cfg) }
func (w *HAWrapper) Stop() error                       { return w.mgr.Stop() }
func (w *HAWrapper) Reload(cfg map[string]string) error { return w.mgr.Reload(cfg) }
func (w *HAWrapper) Status() State                     { return State(w.mgr.Status()) }

func (w *HAWrapper) Validate(cfg map[string]string) error { return w.mgr.Validate(cfg) }

func (w *HAWrapper) DefaultConfig() map[string]string {
	return w.mgr.DefaultConfig()
}

func (w *HAWrapper) ConfigSchema() map[string]ConfigField {
	haSchema := w.mgr.ConfigSchema()
	result := make(map[string]ConfigField, len(haSchema))
	for k, v := range haSchema {
		result[k] = ConfigField{
			Description: v.Description,
			Default:     v.Default,
			Required:    v.Required,
			Type:        v.Type,
		}
	}
	return result
}

// Manager returns the underlying ha.HAManager for direct access.
func (w *HAWrapper) Manager() *ha.HAManager { return w.mgr }

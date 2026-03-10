package service

import (
	"github.com/gatekeeper-firewall/gatekeeper/internal/ipv6"
)

// IPv6RAWrapper adapts ipv6.RouterAdvertisement to the service.Service interface.
type IPv6RAWrapper struct {
	ra *ipv6.RouterAdvertisement
}

func NewIPv6RA() *IPv6RAWrapper {
	return &IPv6RAWrapper{ra: ipv6.NewRouterAdvertisement()}
}

func (w *IPv6RAWrapper) Name() string        { return w.ra.Name() }
func (w *IPv6RAWrapper) DisplayName() string { return w.ra.DisplayName() }
func (w *IPv6RAWrapper) Description() string { return w.ra.Description() }
func (w *IPv6RAWrapper) Category() string    { return w.ra.Category() }
func (w *IPv6RAWrapper) Dependencies() []string { return w.ra.Dependencies() }

func (w *IPv6RAWrapper) Start(cfg map[string]string) error { return w.ra.Start(cfg) }
func (w *IPv6RAWrapper) Stop() error                       { return w.ra.Stop() }
func (w *IPv6RAWrapper) Reload(cfg map[string]string) error { return w.ra.Reload(cfg) }
func (w *IPv6RAWrapper) Status() State                     { return State(w.ra.Status()) }

func (w *IPv6RAWrapper) Validate(cfg map[string]string) error { return w.ra.Validate(cfg) }

func (w *IPv6RAWrapper) DefaultConfig() map[string]string {
	return w.ra.DefaultConfig()
}

func (w *IPv6RAWrapper) ConfigSchema() map[string]ConfigField {
	raSchema := w.ra.ConfigSchema()
	result := make(map[string]ConfigField, len(raSchema))
	for k, v := range raSchema {
		result[k] = ConfigField{
			Description: v.Description,
			Default:     v.Default,
			Required:    v.Required,
			Type:        v.Type,
		}
	}
	return result
}

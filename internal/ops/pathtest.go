package ops

import (
	"fmt"

	"github.com/gatekeeper-firewall/gatekeeper/internal/compiler"
)

// BuildCompilerInput loads all config needed for compilation or path testing.
func (o *Ops) BuildCompilerInput() (*compiler.Input, error) {
	zones, err := o.store.ListZones()
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	aliases, err := o.store.ListAliases()
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}
	policies, err := o.store.ListPolicies()
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	profiles, err := o.store.ListProfiles()
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	devices, err := o.store.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	return &compiler.Input{
		Zones:    zones,
		Aliases:  aliases,
		Policies: policies,
		Profiles: profiles,
		Devices:  devices,
	}, nil
}

// PathTest simulates a packet through the config and returns the result.
func (o *Ops) PathTest(req compiler.PathTestRequest) (*compiler.PathTestResult, error) {
	if req.SrcIP == "" || req.DstIP == "" {
		return nil, fmt.Errorf("src_ip and dst_ip required")
	}
	input, err := o.BuildCompilerInput()
	if err != nil {
		return nil, err
	}
	return compiler.PathTest(input, req), nil
}

// Explain returns a detailed breakdown of all rules for a src→dst pair.
func (o *Ops) Explain(req compiler.PathTestRequest) (*compiler.ExplainResult, error) {
	if req.SrcIP == "" || req.DstIP == "" {
		return nil, fmt.Errorf("src_ip and dst_ip required")
	}
	input, err := o.BuildCompilerInput()
	if err != nil {
		return nil, err
	}
	return compiler.Explain(input, req), nil
}

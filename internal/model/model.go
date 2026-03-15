package model

import "time"

// TrustLevel classifies the trust assigned to a network zone.
type TrustLevel string

const (
	TrustNone   TrustLevel = "none"
	TrustLow    TrustLevel = "low"
	TrustMedium TrustLevel = "medium"
	TrustHigh   TrustLevel = "high"
	TrustFull   TrustLevel = "full"
)

// ValidTrustLevels is the canonical set of allowed trust levels.
var ValidTrustLevels = map[TrustLevel]bool{
	TrustNone: true, TrustLow: true, TrustMedium: true,
	TrustHigh: true, TrustFull: true,
}

// Protocol identifies a transport-layer protocol in firewall rules.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoICMP Protocol = "icmp"
	ProtoNone Protocol = "" // matches any protocol
)

// ValidProtocols is the canonical set of allowed protocol values.
var ValidProtocols = map[Protocol]bool{
	ProtoTCP: true, ProtoUDP: true, ProtoICMP: true, ProtoNone: true,
}

// Zone represents a network segment.
type Zone struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Interface   string     `json:"interface"`
	NetworkCIDR string     `json:"network_cidr"`
	TrustLevel  TrustLevel `json:"trust_level"`
	Description string     `json:"description,omitempty"`
	MTU         int        `json:"mtu,omitempty"` // 0 = inherit from interface (no override)
}

// AliasType defines the kind of alias.
type AliasType string

const (
	AliasTypeHost        AliasType = "host"
	AliasTypeNetwork     AliasType = "network"
	AliasTypePort        AliasType = "port"
	AliasTypeMAC         AliasType = "mac"
	AliasTypeNested      AliasType = "nested"
	AliasTypeExternalURL AliasType = "external_url"
)

// Alias is a named group of addresses, ports, or other aliases.
type Alias struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        AliasType `json:"type"`
	Description string    `json:"description,omitempty"`
	Members     []string  `json:"members,omitempty"`
}

// Profile is a device template assigning zone and policy.
type Profile struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ZoneID      int64  `json:"zone_id"`
	PolicyName  string `json:"policy_name"`
}

// RuleAction defines what to do with matched traffic.
type RuleAction string

const (
	RuleActionAllow  RuleAction = "allow"
	RuleActionDeny   RuleAction = "deny"
	RuleActionReject RuleAction = "reject"
	RuleActionLog    RuleAction = "log"
)

// ValidActions is the canonical set of allowed rule actions.
var ValidActions = map[RuleAction]bool{
	RuleActionAllow: true, RuleActionDeny: true,
	RuleActionReject: true, RuleActionLog: true,
}

// Policy is a named set of rules.
type Policy struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	DefaultAction RuleAction `json:"default_action"`
	Rules         []Rule     `json:"rules,omitempty"`
}

// Rule is a single firewall rule within a policy.
type Rule struct {
	ID          int64      `json:"id"`
	PolicyID    int64      `json:"policy_id"`
	Order       int        `json:"order"`
	SrcAlias    string     `json:"src_alias"`
	DstAlias    string     `json:"dst_alias"`
	Protocol    string     `json:"protocol,omitempty"`
	Ports       string     `json:"ports,omitempty"`
	Action      RuleAction `json:"action"`
	Log         bool       `json:"log"`
	Description string     `json:"description,omitempty"`
}

// DeviceAssignment maps an IP/MAC to a profile.
type DeviceAssignment struct {
	ID         int64     `json:"id"`
	IP         string    `json:"ip"`
	MAC        string    `json:"mac,omitempty"`
	Hostname   string    `json:"hostname,omitempty"`
	ProfileID  int64     `json:"profile_id"`
	AssignedAt time.Time `json:"assigned_at"`
}

// ConfigRevision is an immutable snapshot of a commit.
type ConfigRevision struct {
	ID        int64     `json:"id"`
	RevNumber int       `json:"rev_number"`
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
	Snapshot  string    `json:"snapshot,omitempty"`
}

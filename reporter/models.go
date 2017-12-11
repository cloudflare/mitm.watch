package main

import (
	"net"
	"time"
)

// TODO Frame(s) type/field must be checked carefully.

type Test struct {
	ID            int       `json:"-"`
	TestID        string    `json:"test_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	ClientIP      net.IP    `json:"client_ip"`
	ClientVersion string    `json:"client_version"`
	FlashVersion  string    `json:"flash_version"`
	UserAgent     string    `json:"user_agent"`
	UserComment   string    `json:"user_comment"`
	HasFailed     bool      `json:"has_failed"`
	IsMitm        bool      `json:"is_mitm"`
	IsPending     bool      `json:"is_pending"`
}

// Specification of a subtest
type SubtestSpec struct {
	Number        int    `json:"number"`
	MaxTLSVersion uint16 `json:"max_tls_version"`
	IsIPv6        bool   `json:"is_ipv6"`
}

// Actual instantiation of a subtest.
type Subtest struct {
	ID            int    `json:"-"`
	TestID        int    `json:"-"`
	Number        int    `json:"number"`
	MaxTLSVersion uint16 `json:"max_tls_version"`
	IsIPv6        bool   `json:"is_ipv6"`
	HasFailed     bool   `json:"has_failed"`
	IsMitm        bool   `json:"is_mitm"`
}

type Frame struct {
	Time   time.Time `json:"time"`
	IsRead bool      `json:"is_read"`
	Data   []byte    `json:"data"`
}

type Capture struct {
	ID               int       `json:"-"`
	SubtestID        int       `json:"-"`
	CreatedAt        time.Time `json:"created_at"`
	BeginTime        time.Time `json:"begin_time"`
	EndTime          time.Time `json:"end_time"`
	ActualTLSVersion uint16    `json:"actual_tls_version"`
	Frames           []Frame   `json:"frames"`
	KeyLog           string    `json:"key_log"`
	HasFailed        bool      `json:"has_failed"`
}

type ServerCapture struct {
	Capture
	ClientIP net.IP `json:"client_ip"`
	ServerIP net.IP `json:"server_ip"`
}

type ClientCapture struct {
	Capture
}

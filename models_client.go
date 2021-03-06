// based on reporter/models.go
package main

import (
	"time"
)

type errorResponse struct {
	Error string `json:"error"`
}

type createTestRequest struct {
	ClientVersion string `json:"client_version"`
	FlashVersion  string `json:"flash_version"`
	UserAgent     string `json:"user_agent"`
}

type createTestResponse struct {
	TestID   string        `json:"test_id"`
	Subtests []SubtestSpec `json:"subtests"`
}

// Similar to ClientCapture on the server, but without CreatedAt field.
type clientResult struct {
	BeginTime        time.Time `json:"begin_time"`
	EndTime          time.Time `json:"end_time"`
	ActualTLSVersion uint16    `json:"actual_tls_version"`
	Frames           []Frame   `json:"frames"`
	KeyLog           string    `json:"key_log"`
	HasFailed        bool      `json:"has_failed"`
}

// Specification of a subtest
type SubtestSpec struct {
	Number        int    `json:"number"`
	MaxTLSVersion uint16 `json:"max_tls_version"`
	IsIPv6        bool   `json:"is_ipv6"`
}

type Frame struct {
	Time   time.Time `json:"time"`
	IsRead bool      `json:"is_read"`
	Data   []byte    `json:"data"`
}

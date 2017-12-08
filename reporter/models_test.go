package main

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func parseTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return t
}

func compactJson(data []byte) []byte {
	var buffer bytes.Buffer
	err := json.Compact(&buffer, data)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func TestTestModel(t *testing.T) {
	m := Test{
		ID:            123,
		TestID:        "6b5742d9-722b-4d12-848a-c42da771b806",
		CreatedAt:     parseTime("2017-10-09T19:37:20Z"),
		UpdatedAt:     parseTime("2017-12-07T23:40:36Z"),
		ClientIP:      net.ParseIP("::1"),
		ClientVersion: "123abc",
		FlashVersion:  "10.0",
		UserAgent:     "Mozilla/5.0",
		UserComment:   "works for me",
		HasFailed:     false,
		IsMitm:        false,
		IsPending:     true,
	}
	expected := compactJson([]byte(`{
		"test_id":        "6b5742d9-722b-4d12-848a-c42da771b806",
		"created_at":     "2017-10-09T19:37:20Z",
		"updated_at":     "2017-12-07T23:40:36Z",
		"client_ip":      "::1",
		"client_version": "123abc",
		"flash_version":  "10.0",
		"user_agent":     "Mozilla/5.0",
		"user_comment":   "works for me",
		"has_failed":     false,
		"is_mitm":        false,
		"is_pending":     true
	}`))

	actual, err := json.Marshal(m)
	if err != nil {
		t.Errorf("marshal failed: %v", err)
		return
	}

	if !bytes.Equal(expected, actual) {
		t.Errorf("%v != %v", expected, actual)
	}
}

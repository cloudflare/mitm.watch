package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

// Create a new Test model. Required field: ClientIP. Fields that are updated:
// ID, TestID, CreatedAt, UpdatedAt.
func (model *Test) Create(tx *sql.Tx) error {
	if model.ClientIP == nil {
		return errors.New("client IP must be initialized")
	}
	clientIP := model.ClientIP.String()
	model.TestID = GenerateUUIDv4()
	err := tx.QueryRow(`
	INSERT INTO tests (
		-- id,
		test_id,
		created_at,
		updated_at,
		client_ip,
		client_version,
		flash_version,
		user_agent,
		user_comment,
		has_failed,
		is_mitm,
		is_pending
	) VALUES (
		--     -- id
		$1,    -- test_id
		now(), -- created_at
		now(), -- updated_at
		$2,    -- client_ip
		$3,    -- client_version
		$4,    -- flash_version
		$5,    -- user_agent
		$6,    -- user_comment
		$7,    -- has_failed,
		$8,    -- is_mitm,
		$9     -- is_pending
	) RETURNING
		id, created_at, updated_at
	`,
		//&model.ID,
		&model.TestID,
		//&model.CreatedAt,
		//&model.UpdatedAt,
		&clientIP,
		&model.ClientVersion,
		&model.FlashVersion,
		&model.UserAgent,
		&model.UserComment,
		&model.HasFailed,
		&model.IsMitm,
		&model.IsPending,
	).Scan(
		&model.ID,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	return err
}

// Query the tests model
func QueryTests(db *sql.DB, args ...interface{}) (*sql.Rows, error) {
	extraQuery := ""
	if len(args) > 0 {
		var ok bool
		extraQuery, ok = args[0].(string)
		if !ok {
			return nil, errors.New("argument must be a SQL string")
		}
		args = args[1:]
	}
	rows, err := db.Query(`
	SELECT
		id,
		test_id,
		created_at,
		updated_at,
		client_ip,
		client_version,
		flash_version,
		user_agent,
		user_comment,
		has_failed,
		is_mitm,
		is_pending
	FROM tests
	`+extraQuery, args...)
	return rows, err
}

// Populates a Test model instance from the result set by scanning it.
func ScanTest(rows *sql.Rows) (*Test, error) {
	model := new(Test)
	var clientIP []byte
	err := rows.Scan(
		&model.ID,
		&model.TestID,
		&model.CreatedAt,
		&model.UpdatedAt,
		&clientIP,
		&model.ClientVersion,
		&model.FlashVersion,
		&model.UserAgent,
		&model.UserComment,
		&model.HasFailed,
		&model.IsMitm,
		&model.IsPending,
	)
	if err != nil {
		return nil, err
	}
	model.ClientIP = net.ParseIP(string(clientIP))
	if model.ClientIP == nil {
		return nil, fmt.Errorf("Could not parse client IP: %v", clientIP)
	}
	return model, nil
}

// Create a new Subtest model. Required field: TestID. Fields that is updated:
// ID.
func (model *Subtest) Create(tx *sql.Tx) error {
	err := tx.QueryRow(`
	INSERT INTO subtests (
		-- id,
		test_id,
		number	,
		max_tls_version,
		is_ipv6,
		has_failed,
		is_mitm
	) VALUES (
		--              -- id
		$1,             -- test_id
		$2,             -- number
		$3,             -- max_tls_version
		$4,             -- is_ipv6
		$5,             -- has_failed
		$6              -- is_mitm
	) RETURNING
		id
	`,
		//&model.ID,
		&model.TestID,
		&model.Number,
		&model.MaxTLSVersion,
		&model.IsIPv6,
		&model.HasFailed,
		&model.IsMitm,
	).Scan(
		&model.ID,
	)
	return err
}

// Create a new ClientCapture model. Required field: SubtestID, Frames. Fields
// that are updated: ID, CreatedAt.
func (model *ClientCapture) Create(tx *sql.Tx) error {
	if model.SubtestID == 0 {
		return errors.New("SubtestID must be initialized!")
	}
	if model.Frames == nil {
		return errors.New("Frames must be initialized")
	}
	frames, err := json.Marshal(model.Frames)
	if err != nil {
		return err
	}
	err = tx.QueryRow(`
	INSERT INTO client_captures (
		-- id,
		subtest_id,
		created_at,
		begin_time,
		end_time,
		actual_tls_version,
		frames,
		key_log,
		has_failed
	) VALUES (
		--              -- id,
		$1,             -- subtest_id,
		now(),          -- created_at,
		$2,             -- begin_time,
		$3,             -- end_time,
		$4,             -- actual_tls_version,
		$5,             -- frames,
		$6,             -- key_log,
		$7              -- has_failed
	) RETURNING
		id,
		created_at
	`,
		//&model.ID,
		&model.SubtestID,
		//&model.CreatedAt,
		&model.BeginTime,
		&model.EndTime,
		&model.ActualTLSVersion,
		&frames,
		&model.KeyLog,
		&model.HasFailed,
	).Scan(
		&model.ID,
		&model.CreatedAt,
	)
	return err
}

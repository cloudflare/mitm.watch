package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

const apiPrefix = "/api/v1"

type reporter struct {
	*gin.Engine
	db     *sql.DB
	config Config
}

var errTestNotFound = gin.H{"error": "test not found"}

func stubHandler(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented yet")
}

func authRequired(c *gin.Context) {
	// TODO authentication
	c.Next()
}

func newReporter(db *sql.DB) *reporter {
	router := gin.Default()
	rep := &reporter{router, db, defaultConfig}

	// TODO CSRF protection

	v1 := router.Group(apiPrefix)
	{
		v1.POST("/tests", rep.createTest)
		v1.POST("/tests/:testid/subtests/:number/clientresult", rep.addClientResult)
	}
	authorized := v1.Group("/", authRequired)
	{
		authorized.GET("/tests", rep.listTests)
		authorized.PATCH("/tests/:testid", stubHandler)
		authorized.DELETE("/tests/:testid", rep.removeTest)
		authorized.GET("/tests/:testid", rep.listTest)
		authorized.GET("/tests/:testid/subtests", stubHandler)
		authorized.GET("/tests/:testid/subtests/:number", stubHandler)
		authorized.GET("/tests/:testid/client.pcap", stubHandler)
		authorized.GET("/tests/:testid/server.pcap", stubHandler)
		authorized.GET("/tests/:testid/keylog.txt", stubHandler)
	}

	return rep
}

// Client versions that are allowed to submit tests.
func isAllowedClientVersion(clientVersion string) bool {
	switch clientVersion {
	case "TEST":
		return true
	default:
		return false
	}
}

func (*reporter) dbError(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": "database error",
	})
	fmt.Println(err)
}

func (*reporter) getTestID(c *gin.Context) (string, bool) {
	testID := c.Param("testid")
	if !ValidateUUID(testID) {
		c.JSON(http.StatusNotFound, errTestNotFound)
		return "", false
	}
	return testID, true
}

func (*reporter) getSubtestNumber(c *gin.Context) (int, bool) {
	if n, err := strconv.Atoi(c.Param("number")); err == nil {
		return n, true
	}
	return 0, false
}

type createTestRequest struct {
	ClientVersion string `json:"client_version"`
	FlashVersion  string `json:"flash_version"`
	UserAgent     string `json:"user_agent"`
}

func (r *reporter) createTest(c *gin.Context) {
	var json createTestRequest
	if err := c.BindJSON(&json); err == nil {
		if !isAllowedClientVersion(json.ClientVersion) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid client version",
			})
			return
		}
		// TODO rate limiting

		test := &Test{
			ClientIP:      net.ParseIP(parseHost(c.Request.RemoteAddr)),
			ClientVersion: json.ClientVersion,
			FlashVersion:  json.FlashVersion,
			UserAgent:     json.UserAgent,
			IsPending:     true,
		}
		subtestSpecs := r.config.Subtests

		tx, err := r.db.Begin()
		if err != nil {
			r.dbError(c, err)
			return
		}
		defer func() {
			if tx != nil {
				tx.Rollback()
			}
		}()

		if err = test.Create(tx); err != nil {
			r.dbError(c, err)
			return
		}

		// subtests
		for _, spec := range subtestSpecs {
			subtest := &Subtest{
				TestID:        test.ID,
				Number:        spec.Number,
				MaxTLSVersion: spec.MaxTLSVersion,
				IsIPv6:        spec.IsIPv6,
			}
			if err = subtest.Create(tx); err != nil {
				r.dbError(c, err)
				return
			}
		}

		tx.Commit()
		tx = nil

		c.JSON(http.StatusCreated, gin.H{
			"test_id":  test.TestID,
			"subtests": subtestSpecs,
		})
	}
}

type addClientResultRequest struct {
	Number           int       `json:"number"`
	BeginTime        time.Time `json:"begin_time"`
	EndTime          time.Time `json:"end_time"`
	ActualTLSVersion uint16    `json:"actual_tls_version"`
	Frames           []Frame   `json:"frames"`
	KeyLog           string    `json:"key_log"`
	HasFailed        bool      `json:"has_failed"`
}

func addClientResultRequestToClientCapture(r *addClientResultRequest) (*ClientCapture, error) {
	if len(r.Frames) == 0 {
		return nil, errors.New("Frames is required")
	}
	for frameNo, frame := range r.Frames {
		if len(frame.Data) == 0 {
			return nil, fmt.Errorf("Frame number %d has no data", frameNo+1)
		}
	}

	// unpopulated fields: ID, CreatedAt, SubtestID
	return &ClientCapture{
		Capture{
			BeginTime:        r.BeginTime,
			EndTime:          r.EndTime,
			ActualTLSVersion: r.ActualTLSVersion,
			Frames:           r.Frames,
			KeyLog:           r.KeyLog,
			HasFailed:        r.HasFailed,
		},
	}, nil
}

func (r *reporter) addClientResult(c *gin.Context) {
	testID, ok := r.getTestID(c)
	if !ok {
		return
	}
	subtestNumber, ok := r.getSubtestNumber(c)
	if !ok {
		return
	}

	var json addClientResultRequest
	if err := c.BindJSON(&json); err == nil {
		clientCapture, err := addClientResultRequestToClientCapture(&json)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// check if (sub)test exists and whether it is allowed to be
		// modified (pending)
		var isPending, isEditable bool
		err = r.db.QueryRow(`
		SELECT
			subtests.id,
			is_pending,
			now() - created_at < $3
		FROM tests
		JOIN subtests
		ON tests.id = subtests.test_id
		WHERE 
			tests.test_id = $1 AND
			subtests.number = $2
		`, testID, subtestNumber, r.config.MutableTestPeriodSecs).Scan(
			&clientCapture.SubtestID,
			&isPending,
			&isEditable,
		)
		switch {
		case err == sql.ErrNoRows:
			c.JSON(http.StatusNotFound, errTestNotFound)
			return
		case err != nil:
			r.dbError(c, err)
			return
		}

		// if resource is locked, do not perform further changes.
		if !isPending || !isEditable {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "test can no longer be modified",
			})
			return
		}

		// check for duplicate tests
		var dummy int
		err = r.db.QueryRow(`
		SELECT 1
		FROM client_captures
		WHERE subtest_id = $1
		`, clientCapture.SubtestID).Scan(&dummy)
		switch {
		case err == sql.ErrNoRows:
			// ok, no duplicate.
		case err != nil:
			r.dbError(c, err)
			return
		default:
			c.JSON(http.StatusConflict, gin.H{
				"error": "test submission was already received",
			})
			return
		}

		tx, err := r.db.Begin()
		if err != nil {
			r.dbError(c, err)
			return
		}
		defer func() {
			if tx != nil {
				tx.Rollback()
			}
		}()

		err = clientCapture.Create(tx)
		if err != nil {
			r.dbError(c, err)
			return
		}

		// TODO set IsPending if all subtests are complete

		tx.Commit()
		tx = nil
	}
}

func (r *reporter) listTests(c *gin.Context) {
	rows, err := QueryTests(r.db)
	if err != nil {
		r.dbError(c, err)
		return
	}
	defer rows.Close()

	tests := []*Test{}
	for rows.Next() {
		test, err := ScanTest(rows)
		if err != nil {
			r.dbError(c, err)
			return
		}
		tests = append(tests, test)
	}
	err = rows.Err()
	if err != nil {
		r.dbError(c, err)
		return
	}

	c.JSON(http.StatusOK, tests)
}

func (r *reporter) listTest(c *gin.Context) {
	testID, ok := r.getTestID(c)
	if !ok {
		return
	}
	rows, err := QueryTests(r.db, `WHERE test_id = $1`, testID)
	if err != nil {
		r.dbError(c, err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		test, err := ScanTest(rows)
		if err != nil {
			r.dbError(c, err)
			return
		}
		c.JSON(http.StatusOK, test)
		return
	}

	err = rows.Err()
	if err != nil {
		r.dbError(c, err)
		return
	}

	c.JSON(http.StatusNotFound, errTestNotFound)
}

func (r *reporter) removeTest(c *gin.Context) {
	testID, ok := r.getTestID(c)
	if !ok {
		return
	}
	result, err := r.db.Exec(`DELETE FROM tests WHERE test_id = $1`, testID)
	if err != nil {
		r.dbError(c, err)
		return
	}

	n, err := result.RowsAffected()
	if err != nil {
		r.dbError(c, err)
		return
	}

	if n > 0 {
		c.Status(http.StatusNoContent)
		return
	}

	c.JSON(http.StatusNotFound, errTestNotFound)
}

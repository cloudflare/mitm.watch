package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type reporter struct {
	*gin.Engine
	db     *sql.DB
	config *Config
}

var errTestNotFound = gin.H{"error": "test not found"}
var errSubTestNotFound = gin.H{"error": "subtest not found"}
var errCsrf = gin.H{"error": "missing X-Requested-With header"}

func stubHandler(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented yet")
}

// csrfProtection requires the X-Requested-With header to be set for requests
// with non-safe methods.
func csrfProtection(c *gin.Context) {
	method := c.Request.Method
	if !(method == "HEAD" || method == "GET" || method == "OPTIONS") &&
		c.GetHeader("X-Requested-With") == "" {
		c.AbortWithStatusJSON(http.StatusForbidden, errCsrf)
		return
	}
	c.Next()
}

func authRequired(c *gin.Context) {
	// TODO authentication
	c.Next()
}

func newReporter(db *sql.DB, config *Config) *reporter {
	router := gin.Default()
	rep := &reporter{router, db, config}

	v1 := router.Group(config.ReporterApiPrefix)
	v1.Use(csrfProtection)
	{
		v1.POST("/tests", rep.createTest)
		v1.PATCH("/tests/:testid", rep.updateTest)
		v1.PUT("/tests/:testid/subtests/:number/clientresult", rep.addClientResult)
	}
	authorized := v1.Group("/", authRequired)
	{
		authorized.GET("/tests", rep.listTests)
		authorized.DELETE("/tests/:testid", rep.removeTest)
		authorized.GET("/tests/:testid", rep.listTest)
		authorized.GET("/tests/:testid/subtests", stubHandler)
		authorized.GET("/tests/:testid/subtests/:number", stubHandler)
		authorized.GET("/tests/:testid/client.pcap", stubHandler)
		authorized.GET("/tests/:testid/server.pcap", stubHandler)
		authorized.GET("/tests/:testid/keylog.txt", stubHandler)
	}

	if config.ReporterStaticFilesRoot != "" {
		prefixLen := len(config.ReporterStaticFilesRoot)
		filepath.Walk(config.ReporterStaticFilesRoot,
			func(fullPath string, info os.FileInfo, err error) error {
				// do not accidentally serve hidden files.
				if path.Base(fullPath)[0] == '.' {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if !info.IsDir() && err == nil {
					// /myroot/index.html -> /index.html
					webPath := fullPath[prefixLen:]
					if webPath == "/index.html" {
						webPath = "/"
					}

					// Do not serve compressed files
					// directly, but do serve it when the
					// client has an acceptable
					// content-encoding.
					if strings.HasSuffix(webPath, ".gz") {
						return nil
					}

					StaticFileGz(router, webPath, fullPath)
				}
				return nil
			})
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

// checkTestEditAllowed checks whether a test exists and whether it is allowed
// to be modified given the elapsed time. If edits are allowed, the internal
// TestID is and true is returned.
func (r *reporter) checkTestEditAllowed(c *gin.Context) (int, bool) {
	testID, ok := r.getTestID(c)
	if !ok {
		return 0, false
	}
	var testIDKey int
	var isPending, isEditable bool
	err := r.db.QueryRow(`
	SELECT
		id,
		is_pending,
		now() - created_at < $2
	FROM tests
	WHERE
		tests.test_id = $1
	`, testID, r.config.MutableTestPeriodSecs).Scan(
		&testIDKey,
		&isPending,
		&isEditable,
	)
	switch {
	case err == sql.ErrNoRows:
		c.JSON(http.StatusNotFound, errTestNotFound)
		return 0, false
	case err != nil:
		r.dbError(c, err)
		return 0, false
	}

	// if resource is locked, do not perform further changes.
	if !isPending || !isEditable {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "test can no longer be modified",
		})
		return 0, false
	}
	return testIDKey, true
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

		anonymousValue, anonymousSet := c.GetQuery("anonymous")
		if anonymousValue == "" && anonymousSet {
			// create surrogate identifier (it is needed to create a
			// random domain)
			test.TestID = "otr-" + GenerateUUIDv4()
		} else {
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
		}

		c.JSON(http.StatusCreated, gin.H{
			"test_id":  test.TestID,
			"subtests": subtestSpecs,
		})
	}
}

type updateTestRequest struct {
	UserComment *string `json:"user_comment"`
	IsPending   *bool   `json:"is_pending"`
}

func (r *reporter) updateTest(c *gin.Context) {
	testIDKey, ok := r.checkTestEditAllowed(c)
	if !ok {
		return
	}

	var json updateTestRequest
	if err := c.BindJSON(&json); err == nil {
		if json.UserComment == nil && (json.IsPending == nil || *json.IsPending == true) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "no changes requested",
			})
			return
		}

		// update fields if allowed
		result, err := r.db.Exec(`
		UPDATE tests
		SET
			user_comment = COALESCE($2, user_comment),
			is_pending = COALESCE($3, is_pending)
		WHERE id = $1 AND is_pending
		`, testIDKey, json.UserComment, json.IsPending)
		if err != nil {
			r.dbError(c, err)
			return
		}
		n, err := result.RowsAffected()
		if err != nil {
			r.dbError(c, err)
			return
		}
		if n == 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "test can no longer be modified",
			})
			return
		}

		c.Status(http.StatusNoContent)
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
	testIDKey, ok := r.checkTestEditAllowed(c)
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

		// check for duplicate tests
		var clientCaptureCount sql.NullInt64
		err = r.db.QueryRow(`
		SELECT
			subtests.id,
			client_captures.id
		FROM subtests
		LEFT JOIN client_captures
		ON subtests.id = client_captures.subtest_id
		WHERE
			subtests.test_id = $1 AND
			subtests.number = $2
		`, testIDKey, subtestNumber).Scan(&clientCapture.SubtestID, &clientCaptureCount)
		switch {
		case err == sql.ErrNoRows:
			// unknown subtest (or test was quickly deleted)
			c.JSON(http.StatusNotFound, errSubTestNotFound)
			return
		case err != nil:
			r.dbError(c, err)
			return
		case clientCaptureCount.Valid:
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

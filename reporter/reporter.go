package main

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

const apiPrefix = "/api/v1"

type reporter struct {
	*gin.Engine
	db *sql.DB
}

func stubHandler(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented yet")
}

func authRequired(c *gin.Context) {
	// TODO authentication
	c.Next()
}

func newReporter(db *sql.DB) *reporter {
	router := gin.Default()
	rep := &reporter{router, db}

	// TODO CSRF protection

	v1 := router.Group(apiPrefix)
	{
		v1.POST("/tests", rep.createTest)
	}
	authorized := v1.Group("/", authRequired)
	{
		authorized.GET("/tests", rep.listTests)
		authorized.POST("/tests/:testid/clientresults", stubHandler)
		authorized.PATCH("/tests/:testid", stubHandler)
		authorized.DELETE("/tests/:testid", stubHandler)
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
		c.JSON(http.StatusNotFound, gin.H{
			"error": "test not found",
		})
		return "", false
	}
	return testID, true
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
		subtestSpecs := defaultConfig.Subtests

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

	c.JSON(http.StatusNotFound, gin.H{
		"error": "test not found",
	})
}

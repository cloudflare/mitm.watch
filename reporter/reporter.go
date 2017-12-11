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

func newReporter(db *sql.DB) *reporter {
	router := gin.Default()
	rep := &reporter{router, db}

	// TODO CSRF protection
	// TODO authentication

	v1 := router.Group(apiPrefix)
	{
		v1.POST("/tests", rep.createTest)
		v1.GET("/tests", stubHandler)
		v1.POST("/tests/:testid/clientresults", stubHandler)
		v1.PATCH("/tests/:testid", stubHandler)
		v1.DELETE("/tests/:testid", stubHandler)
		v1.GET("/tests/:testid", stubHandler)
		v1.GET("/tests/:testid/subtests", stubHandler)
		v1.GET("/tests/:testid/subtests/:number", stubHandler)
		v1.GET("/tests/:testid/client.pcap", stubHandler)
		v1.GET("/tests/:testid/server.pcap", stubHandler)
		v1.GET("/tests/:testid/keylog.txt", stubHandler)
	}

	return rep
}

type createTestRequest struct {
	ClientVersion string `json:"client_version"`
	FlashVersion  string `json:"flash_version"`
	UserAgent     string `json:"user_agent"`
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

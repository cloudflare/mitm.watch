package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type reporter struct {
	*gin.Engine
}

const apiPrefix = "/api/v1"

func stubHandler(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented yet")
}

func newReporter() *reporter {
	router := gin.Default()
	rep := &reporter{router}

	// TODO CSRF protection
	// TODO authentication

	v1 := router.Group(apiPrefix)
	{
		v1.POST("/tests", stubHandler)
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

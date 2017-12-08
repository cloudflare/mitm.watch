package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type reporter struct {
	*httprouter.Router
}

const apiPrefix = "/api"

func stubHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	http.Error(w, "not implemented yet", 501)
}

func newReporter() *reporter {
	router := httprouter.New()

	// TODO CSRF protection
	// TODO authentication

	router.POST(apiPrefix+"/tests", stubHandler)
	router.GET(apiPrefix+"/tests", stubHandler)
	router.POST(apiPrefix+"/tests/:testid/clientresults", stubHandler)
	router.PATCH(apiPrefix+"/tests/:testid", stubHandler)
	router.DELETE(apiPrefix+"/tests/:testid", stubHandler)
	router.GET(apiPrefix+"/tests/:testid", stubHandler)
	router.GET(apiPrefix+"/tests/:testid/subtests", stubHandler)
	router.GET(apiPrefix+"/tests/:testid/subtests/:number", stubHandler)
	router.GET(apiPrefix+"/tests/:testid/client.pcap", stubHandler)
	router.GET(apiPrefix+"/tests/:testid/server.pcap", stubHandler)
	router.GET(apiPrefix+"/tests/:testid/keylog.txt", stubHandler)

	return &reporter{router}
}

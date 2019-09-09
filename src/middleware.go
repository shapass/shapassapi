package main

import (
	"fmt"
	"net/http"

	"./models"
)

func allowCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,OPTIONS,POST")
	w.Header().Set("Access-Control-Allow-Headers", "Access-Control-Allow-Headers, Origin, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers")
}

func allowOnlyPOST(r *http.Request, apiPath string) error {
	if r.Method != http.MethodPost {
		return fmt.Errorf("The %s API requires POST", apiPath)
	}

	return nil
}

func CheckRequest(w http.ResponseWriter, r *http.Request) bool {
	allowCORS(w)

	// Allow only POST requests
	err := allowOnlyPOST(r, r.URL.Path)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidMethod, "%v", err)
		return false
	}

	return true
}

func HandleMiddleware(next func(http.ResponseWriter, *http.Request), mids ...func(http.ResponseWriter, *http.Request) bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, f := range mids {
			if !f(w, r) {
				return
			}
		}
		next(w, r)
	}
}

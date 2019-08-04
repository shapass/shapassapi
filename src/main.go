package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"./data"
)

var db *sql.DB

func HandleTeapot(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot)
}

var globalEmail string
var globalEmailPassword string
var globalShapassResetLink string

func main() {
	var err error
	db, err = data.OpenDatabase("localhost")
	if err != nil {
		os.Exit(1)
	}
	go data.CheckDatabase(db)

	globalEmailPassword = os.Getenv("ZOHO_SHAPASS_EMAIL_PASSWORD")
	globalEmail = os.Getenv("ZOHO_SHAPASS_EMAIL")
	globalShapassResetLink = "https://shapass.com/shapass/reset"

	http.HandleFunc("/v2/signup", HandleMiddleware(HandleSignUpV2, CheckRequest))
	http.HandleFunc("/v2/login", HandleMiddleware(HandleLoginV2, CheckRequest))
	http.HandleFunc("/v2/list", HandleMiddleware(HandleListV2, CheckRequest))
	http.HandleFunc("/v2/create", HandleMiddleware(HandleCreateV2, CheckRequest))
	http.HandleFunc("/v2/delete", HandleMiddleware(HandleDeleteV2, CheckRequest))
	http.HandleFunc("/v2/whoami", HandleMiddleware(HandleWhoAmIV2, CheckRequest))
	http.HandleFunc("/v2/logout", HandleMiddleware(HandleLogoutV2, CheckRequest))
	http.HandleFunc("/v2/deleteaccount", HandleMiddleware(HandleDeleteAccount, CheckRequest))
	http.HandleFunc("/v2/resetpassword", HandleMiddleware(HandleResetPassword, CheckRequest))

	//http.HandleFunc("/v2/sync", HandleMiddleware(HandleSyncV2, CheckRequest))

	// Ok, this is a joke
	http.HandleFunc("/teapot", HandleTeapot)

	fmt.Println("Listening on port 8888...")
	/*
		@Important: We need to run only allowing 127.0.0.1 (localhost) connections.
		This is because no firewall rule is set to block port 8000, meaning an http
		connection would not be blocked and we would not be encrypting. Oh no!
		Keep the listen this way! Apache is redirecting /api to this service.
	*/
	http.ListenAndServe("127.0.0.1:8888", nil)
}

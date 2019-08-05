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
	dbport := os.Getenv("SHAPASS_DATABASE_PORT")
	dbhost := os.Getenv("SHAPASS_DATABASE_HOST")
	dbpass := os.Getenv("SHAPASS_DATABASE_PASSWORD")

	if dbport == "" {
		dbport = "5432"
	}
	if dbhost == "" {
		dbhost = "localhost"
	}
	if dbpass == "" {
		dbpass = "postgres"
	}

	var err error
	db, err = data.OpenDatabase(dbhost, dbport, dbpass)
	if err != nil {
		os.Exit(1)
	}
	go data.CheckDatabase(db)

	globalEmailPassword = os.Getenv("ZOHO_SHAPASS_EMAIL_PASSWORD")
	globalEmail = os.Getenv("ZOHO_SHAPASS_EMAIL")
	globalShapassResetLink = "https://shapass.com/shapass/reset"

	http.HandleFunc("/signup", HandleMiddleware(HandleSignUpV2, CheckRequest))
	http.HandleFunc("/login", HandleMiddleware(HandleLoginV2, CheckRequest))
	http.HandleFunc("/list", HandleMiddleware(HandleListV2, CheckRequest))
	http.HandleFunc("/create", HandleMiddleware(HandleCreateV2, CheckRequest))
	http.HandleFunc("/delete", HandleMiddleware(HandleDeleteV2, CheckRequest))
	http.HandleFunc("/whoami", HandleMiddleware(HandleWhoAmIV2, CheckRequest))
	http.HandleFunc("/logout", HandleMiddleware(HandleLogoutV2, CheckRequest))
	http.HandleFunc("/deleteaccount", HandleMiddleware(HandleDeleteAccount, CheckRequest))
	http.HandleFunc("/resetpassword", HandleMiddleware(HandleResetPassword, CheckRequest))

	// Ok, this is a joke
	http.HandleFunc("/teapot", HandleTeapot)

	/*
		@Important: We need to run only allowing 127.0.0.1 (localhost) connections.
		This is because no firewall rule is set to block port 8000, meaning an http
		connection would not be blocked and we would not be encrypting. Oh no!
		Keep the listen this way! Apache is redirecting /api to this service.
	*/
	apiHost := os.Getenv("SHAPASS_API_HOST")
	if apiHost == "" {
		apiHost = "127.0.0.1"
	}

	fmt.Printf("Listening on %s:8000...\n", apiHost)
	http.ListenAndServe(apiHost+":8000", nil)
}

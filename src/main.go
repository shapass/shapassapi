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

func main() {
	var err error
	db, err = data.OpenDatabase()
	if err != nil {
		os.Exit(1)
	}
	go data.CheckDatabase(db)

	http.HandleFunc("/login", HandleMiddleware(HandleLogin, CheckRequest))
	http.HandleFunc("/signup", HandleMiddleware(HandleSignUp, CheckRequest))
	http.HandleFunc("/whoami", HandleMiddleware(HandleWhoAmI, CheckRequest))
	http.HandleFunc("/create", HandleMiddleware(HandleCreate, CheckRequest))
	http.HandleFunc("/delete", HandleMiddleware(HandleDelete, CheckRequest))
	http.HandleFunc("/logout", HandleMiddleware(HandleLogout, CheckRequest))
	http.HandleFunc("/list", HandleMiddleware(HandleList, CheckRequest))
	http.HandleFunc("/sync", HandleMiddleware(HandleSync, CheckRequest))

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

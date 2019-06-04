package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"./data"
)

var db *sql.DB
var connected bool

func getIntLengthFromString(length string) int {
	var l int64
	if length == "" {
		l = 32
	} else {
		var err error
		l, err = strconv.ParseInt(length, 10, 64)
		if err != nil {
			l = 32
		}
	}
	return int(l)
}

// loggedIn returns if the user has a valid login and its username in the positive case.
func loggedIn(r *http.Request) (bool, string) {
	cookie, err := r.Cookie("login")
	if err != nil {
		return false, ""
	}
	logged, user := data.UserLoggedIn(db, cookie.Value)
	return logged, user.Name.String
}

// HandleSignUp creates a new user in the database if one does not already exist.
// Requires fields:
// 	- username
//  - password
//  - email
func HandleSignUp(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// Check if the user is already logged in, cannot sign up while logged in
	currentCookie, err := r.Cookie("login")
	logged := false
	if err == nil {
		logged, _ = data.UserLoggedIn(db, currentCookie.Value)
	}

	if logged {
		// Cannot sign up if logged in
		LogAndRespond(w, StatusError, "Unable to sign up, logout first")
		return
	}

	// Check fields necessary
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	email := r.Form.Get("email")

	if username == "" || password == "" || email == "" {
		LogAndRespond(w, StatusError, "Sign up requires fields username, password and email")
		return
	}

	// Check if the user already exist, if so, error out
	if data.UserExists(db, username) {
		LogAndRespond(w, StatusError, "User %s already exist and cannot be created", username)
		return
	}

	// Everything is fine, create the user
	err = data.CreateUser(db, username, password, email)

	if err != nil {
		LogAndRespond(w, StatusError, "Could not create user, service unavailable")
		return
	}

	LogAndRespond(w, StatusOK, "User %s signed up successfully!", username)
}

// HandleLogin logins user if it exists and the password matches the one in the database
// This creates a cookie with key "login" that it saves in the database as the last valid
// login.
// Requires fields:
//  - username
//  - password
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if username == "" || password == "" {
		LogAndRespond(w, StatusError, "Login requires fields username and password")
		return
	}

	// Check if the user is already logged in, as the same user or not.
	// Do not attempt to log in if so.
	logged, u := loggedIn(r)
	if logged {
		if username == u {
			LogAndRespond(w, StatusError, "Already logged in as %s", u)
		} else {
			LogAndRespond(w, StatusError, "Already logged in as %s, logout first", u)
		}
		return
	}

	// String that will be the cookie
	str, err := GenerateRandomString(128)
	if err != nil {
		LogAndRespond(w, StatusError, "Error trying to login")
		return
	}

	// Everything is good, try to log in
	success, err := data.Login(db, username, password, str)

	// Unable to login
	if !success {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	// We could login successfully, set cookie in the client and report success
	c := http.Cookie{
		Name:  "login",
		Value: str,
	}
	http.SetCookie(w, &c)

	LogAndRespond(w, StatusOK, "User %s logged in successfully!", username)
}

// HandleLogout deletes the current user login cookie from the database
// and the client browser.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	currentCookie, err := r.Cookie("login")
	if err != nil {
		// No cookie
		LogAndRespond(w, StatusError, "User not logged in")
		return
	}

	err = data.InvalidateLogin(db, currentCookie.Value)
	if err != nil {
		LogAndRespond(w, StatusError, "User not logged in")
		return
	}

	// Clear cookie from clients browser
	c := http.Cookie{
		Name:  "login",
		Value: "",
	}
	http.SetCookie(w, &c)

	LogAndRespond(w, StatusOK, "Logged out successfully!")
}

func HandleDelete(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// If the cookie doesn't exist, the user is not logged in
	cookie, err := r.Cookie("login")
	if err != nil {
		LogAndRespond(w, StatusError, "Not logged in")
		return
	}

	// Check is the user is logged in
	logged, user := data.UserLoggedIn(db, cookie.Value)
	if !logged {
		// Try anyway with username and password
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			LogAndRespond(w, StatusError, "Not logged in")
			return
		}
		_, err := data.PasswordMatches(db, username, password)
		if err != nil {
			LogAndRespond(w, StatusError, "%v", err)
			return
		}
		user.Name.String = username
		user.Name.Valid = true
	}

	serviceName := r.Form.Get("name")
	if serviceName == "" {
		LogAndRespond(w, StatusError, "Service name required to delete rule")
		return
	}

	err = data.DeleteRule(db, user.Name.String, serviceName)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "Deleted service %s successfully!", serviceName)
}

// HandleCreate creates a rule for a password in the database
// if one of the same name does not exist.
// Fields:
//   - name 	: required, name of the service to be created
//   - length   : optional, default 32, length of the final generated password
//   - prefix   : optional, prefix for the password
//   - suffix   : optional, suffix for the password
//
// this can optionally be called with the fields:
//   - username
//   - password
// to directly create a rule without being logged in
func HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// If the cookie doesn't exist, the user is not logged in
	cookie, err := r.Cookie("login")
	if err != nil {
		LogAndRespond(w, StatusError, "Not logged in")
		return
	}

	// Check is the user is logged in
	logged, user := data.UserLoggedIn(db, cookie.Value)
	if !logged {
		// Try anyway with username and password
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			LogAndRespond(w, StatusError, "Not logged in")
			return
		}
		_, err := data.PasswordMatches(db, username, password)
		if err != nil {
			LogAndRespond(w, StatusError, "%v", err)
			return
		}
		user.Name.String = username
		user.Name.Valid = true
	}

	prefix := r.Form.Get("prefix")
	suffix := r.Form.Get("suffix")
	length := r.Form.Get("length")
	name := r.Form.Get("name")

	// Check required fields
	if name == "" {
		LogAndRespond(w, StatusError, "Service name required to create rule")
		return
	}

	// get length, default is 32
	l := getIntLengthFromString(length)

	err = data.CreateRuleForUser(db, user, prefix, suffix, l, name)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "Created rule successfully!")
}

func HandleList(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// If the cookie doesn't exist, the user is not logged in
	cookie, err := r.Cookie("login")
	if err != nil {
		LogAndRespond(w, StatusError, "Not logged in")
		return
	}

	// Check is the user is logged in
	logged, user := data.UserLoggedIn(db, cookie.Value)
	if !logged {
		// Try anyway with username and password
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if username == "" || password == "" {
			LogAndRespond(w, StatusError, "Not logged in")
			return
		}
		_, err := data.PasswordMatches(db, username, password)
		if err != nil {
			LogAndRespond(w, StatusError, "%v", err)
			return
		}
		user.Name.String = username
		user.Name.Valid = true
	}

	rules, err := data.RulesList(db, user.Name.String)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespondList(w, StatusOK, rules, "Rules successfully fetched")
}

// CheckDatabase tries to reconnect to the database when the connection
// is lost. This function is asyncronous
func CheckDatabase(db *sql.DB) {
	for {
		err := db.Ping()
		if err != nil {
			fmt.Println(err)
			connected = false
		} else {
			if !connected {
				fmt.Println("Connected")
			}
			connected = true
		}
		time.Sleep(time.Second * 3)
	}
}

func main() {
	var err error
	db, err = data.OpenDatabase()
	if err != nil {
		os.Exit(1)
	}
	go CheckDatabase(db)

	http.HandleFunc("/api/create", HandleCreate)
	http.HandleFunc("/api/delete", HandleDelete)
	http.HandleFunc("/api/login", HandleLogin)
	http.HandleFunc("/api/signup", HandleSignUp)
	http.HandleFunc("/api/logout", HandleLogout)
	http.HandleFunc("/api/list", HandleList)

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/", fs)

	fmt.Println("Listening on port 8000...")
	http.ListenAndServe(":8000", nil)
}

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

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

// loggedIn returns if the user has a valid login and its email in the positive case.
func loggedIn(r *http.Request) (bool, string) {
	cookie, err := r.Cookie("login")
	if err != nil {
		return false, ""
	}
	logged, user := data.UserLoggedIn(db, cookie.Value)
	return logged, user.Email.String
}

// HandleSignUp creates a new user in the database if one does not already exist.
// Requires fields:
//  - password
//  - email
func HandleSignUp(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Access-Control-Allow-Origin", "*")

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
	password := r.Form.Get("password")
	email := r.Form.Get("email")

	if strings.ContainsRune(email, ':') {
		LogAndRespond(w, StatusError, "Invalid email, character ':' is not allowed")
		return
	}
	if password == "" || email == "" {
		LogAndRespond(w, StatusError, "Sign up requires fields password and email")
		return
	}

	// Check if the user already exist, if so, error out
	if data.UserExists(db, email) {
		LogAndRespond(w, StatusError, "User %s already exist and cannot be created", email)
		return
	}

	// Everything is fine, create the user
	err = data.CreateUser(db, email, password)

	if err != nil {
		LogAndRespond(w, StatusError, "Could not create user, service unavailable")
		return
	}

	LogAndRespond(w, StatusOK, "User %s signed up successfully!", email)
}

// HandleLogin logins user if it exists and the password matches the one in the database
// This creates a cookie with key "login" that it saves in the database as the last valid
// login.
// Requires fields:
//  - email
//  - password
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Access-Control-Allow-Origin", "*")

	email := r.Form.Get("email")
	password := r.Form.Get("password")

	if email == "" || password == "" {
		LogAndRespond(w, StatusError, "Login requires fields email and password")
		return
	}

	// Check if the user is already logged in, as the same user or not.
	// Do not attempt to log in if so.
	logged, u := loggedIn(r)
	if logged {
		if email == u {
			LogAndRespond(w, StatusError, "Already logged in as %s", u)
		} else {
			LogAndRespond(w, StatusError, "Already logged in as %s, logout first", u)
		}
		return
	}

	// String that will be the cookie is always 64 bytes long,
	// this will be used to determine where the user email ends
	// since it is concatenated in the cookie in the form:
	// user@email.com:cookie
	str, err := GenerateRandomString(64)
	str = email + ":" + str
	cc, err := bcrypt.GenerateFromPassword([]byte(str), 10)
	if err != nil {
		LogAndRespond(w, StatusError, "Error trying to login")
		return
	}

	// Everything is good, try to log in
	success, err := data.Login(db, email, password, string(cc))

	// Unable to login
	if !success {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	// We could login successfully, set cookie in the client and report success
	c := http.Cookie{
		Name:  "login",
		Value: string(str),
	}
	http.SetCookie(w, &c)

	LogAndRespond(w, StatusOK, "User %s logged in successfully!", email)
}

// HandleLogout deletes the current user login cookie from the database
// and the client browser.
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Access-Control-Allow-Origin", "*")

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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	user, err := checkLogin(r)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	serviceName := r.Form.Get("name")
	if serviceName == "" {
		LogAndRespond(w, StatusError, "Service name required to delete rule")
		return
	}

	err = data.DeleteRule(db, user.Email.String, serviceName)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "Deleted service %s successfully!", serviceName)
}

func checkLogin(r *http.Request) (data.User, error) {
	// If the cookie doesn't exist, the user is not logged in
	cookie, err := r.Cookie("login")
	var logged bool
	var user data.User
	if err != nil {
		return data.User{}, fmt.Errorf("User not logged in")
	}

	// Check is the user is logged in
	logged, user = data.UserLoggedIn(db, cookie.Value)
	if !logged {
		// Try anyway with email and password
		email := r.Form.Get("email")
		password := r.Form.Get("password")
		if email == "" || password == "" {
			return data.User{}, fmt.Errorf("Not logged in")
		}
		_, err := data.PasswordMatches(db, email, password)
		if err != nil {
			return data.User{}, fmt.Errorf("%v", err)
		}
		user.Email.String = email
		user.Email.Valid = true
	}
	return user, nil
}

func HandleSync(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Access-Control-Allow-Origin", "*")

	user, err := checkLogin(r)
	if err != nil {
		LogAndRespond(w, StatusError, fmt.Sprintf("%v", err))
		return
	}

	type Service struct {
		Time int64 `json:"time"`
		Data struct {
			OutputLength int    `json:"outputLength"`
			Suffix       string `json:"sufix"`
		} `json:"data"`
	}
	type SyncData struct {
		Configs map[string]Service `json:"configs"`
		Time    int64              `json:"time"`
	}

	syncStr := r.Form.Get("data")
	if syncStr == "" {
		LogAndRespond(w, StatusError, "sync api call requires data field")
		return
	}

	var rawRules SyncData
	err = json.Unmarshal([]byte(syncStr), &rawRules)
	if err != nil {
		LogAndRespond(w, StatusError, "Invalid format for sync: %v", err)
		return
	}

	rules := []data.ShaPassRule{}
	for k, r := range rawRules.Configs {
		rules = append(rules, data.ShaPassRule{
			Name:   k,
			Length: r.Data.OutputLength,
			Suffix: r.Data.Suffix,
		})
	}

	errs := data.SyncRules(db, rules, user.Email.String)
	if len(errs) > 0 {
		LogAndRespond(w, StatusError, fmt.Sprint(errs))
		return
	}

	LogAndRespond(w, StatusOK, "Sync successful!")
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
//   - email
//   - password
// to directly create a rule without being logged in
func HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Access-Control-Allow-Origin", "*")

	user, err := checkLogin(r)
	if err != nil {
		LogAndRespond(w, StatusError, fmt.Sprintf("%v", err))
		return
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
	w.Header().Set("Access-Control-Allow-Origin", "*")

	user, err := checkLogin(r)
	if err != nil {
		LogAndRespond(w, StatusError, fmt.Sprintf("%v", err))
		return
	}

	rules, err := data.RulesList(db, user.Email.String)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespondList(w, StatusOK, rules, "Rules successfully fetched")
}

func HandleTeapot(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusTeapot)
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

	http.HandleFunc("/create", HandleCreate)
	http.HandleFunc("/delete", HandleDelete)
	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/signup", HandleSignUp)
	http.HandleFunc("/logout", HandleLogout)
	http.HandleFunc("/list", HandleList)
	http.HandleFunc("/sync", HandleSync)

	// Ok, this is a joke
	http.HandleFunc("/teapot", HandleTeapot)

	fmt.Println("Listening on port 8000...")
	/*
		@Important: We need to run only allowing 127.0.0.1 (localhost) connections.
		This is because no firewall rule is set to block port 8000, meaning an http
		connection would not be blocked and we would not be encrypting. Oh no!
		Keep the listen this way! Apache is redirecting /api to this service.
	*/
	http.ListenAndServe("127.0.0.1:8000", nil)
}

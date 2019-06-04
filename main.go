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

func HandleSignUp(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.Form.Get("username")
	password := r.Form.Get("password")
	email := r.Form.Get("email")

	currentCookie, err := r.Cookie("login")
	logged := false
	if err == nil {
		logged, _ = data.UserLoggedIn(db, currentCookie.Value)
	}

	if logged {
		// Cannot sign up if logged in
		fmt.Println("Unable to sign up, logout first")
		fmt.Fprintf(w, "Unable to sign up, you must logout first")
		return
	}

	if data.UserExists(db, username) {
		// Error, user already exists
		fmt.Printf("User %s already exist and cannot be created\n", username)
		fmt.Fprintf(w, "User %s already exist and cannot be created\n", username)
	} else {
		err := data.CreateUser(db, username, password, email)
		if err != nil {
			fmt.Printf("%s could not sign up: %v\n", username, err)
			fmt.Fprintf(w, "Error, could not sign up!\n")
		} else {
			fmt.Printf("user %s signed up successfully!\n", username)
			fmt.Fprintf(w, "user %s signed up successfully!\n", username)
		}
	}
}

func loggedIn(r *http.Request) (bool, string) {
	cookie, err := r.Cookie("login")
	if err != nil {
		return false, ""
	}
	logged, user := data.UserLoggedIn(db, cookie.Value)
	return logged, user.Name.String
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	str, err := GenerateRandomString(128)
	if err != nil {
		fmt.Fprintf(w, "Request error")
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	logged, u := loggedIn(r)
	if logged {
		if username == u {
			fmt.Fprintf(w, "Already logged in as %s\n", u)
		} else {
			fmt.Fprintf(w, "Already logged in as %s, log out first\n", u)
		}
		return
	}

	success, err := data.Login(db, username, password, str)
	if success {
		c := http.Cookie{
			Name:  "login",
			Value: str,
		}
		http.SetCookie(w, &c)
		fmt.Printf("user %s logged in with cookie %s...\n", username, str[:32])
		fmt.Fprintf(w, "Logged in successfully as %s", username)
	} else {
		fmt.Fprintf(w, "%v", err)
	}
}

func HandleLogout(w http.ResponseWriter, r *http.Request) {
	currentCookie, _ := r.Cookie("login")
	err := data.InvalidateLogin(db, currentCookie.Value)
	if err != nil {
		fmt.Println(err)
		return
	}

	c := http.Cookie{
		Name:  "login",
		Value: "",
	}
	http.SetCookie(w, &c)
	fmt.Println("Logout...")
	fmt.Fprintf(w, "Logout...")
}

func HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	cookie, err := r.Cookie("login")
	if err != nil {
		// Not logged in
		fmt.Fprintln(w, "Not logged in!")
		return
	}
	logged, user := data.UserLoggedIn(db, cookie.Value)

	if logged {
		prefix := r.Form.Get("prefix")
		suffix := r.Form.Get("suffix")
		length := r.Form.Get("length")
		name := r.Form.Get("name")

		if name == "" {
			fmt.Fprintf(w, "Require service name to create pattern")
			return
		}

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

		err := data.CreateRuleForUser(db, user, prefix, suffix, int(l), name)
		if err != nil {
			fmt.Fprintf(w, "%v", err)
		} else {
			fmt.Fprintf(w, "Created rule successfully!")
		}

	} else {
		fmt.Fprintln(w, "Not logged in!")
	}
}

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
	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/signup", HandleSignUp)
	http.HandleFunc("/logout", HandleLogout)

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/", fs)

	fmt.Println("Listening on port 8000...")
	http.ListenAndServe(":8000", nil)
}

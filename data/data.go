package data

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	_ "github.com/lib/pq" // needed to start the postgres driver
)

type ShaPassRule struct {
	Name   string
	Length int
	Prefix string
	Suffix string
}

type User struct {
	Name        sql.NullString
	Password    sql.NullString
	Email       sql.NullString
	LoginCookie sql.NullString
	LoginValid  sql.NullBool
}

func OpenDatabase() (*sql.DB, error) {
	host := "localhost"
	port := "5432"
	user := "admin"
	password := "postgres"
	database := "shapass"
	ssl := "disable"

	db, err := sql.Open("postgres", fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host,
		port,
		user,
		password,
		database,
		ssl),
	)
	if err != nil {
		fmt.Println("Could not connect to database: ", err)
		return nil, err
	}

	return db, nil
}

func Sha256String(s string) string {
	bytes := sha256.Sum256([]byte(s))
	return hex.EncodeToString(bytes[:])
}

func PasswordMatches(db *sql.DB, username string, password string) (bool, error) {
	query := "SELECT password FROM users WHERE name=$1"
	row := db.QueryRow(query, username)

	var pw sql.NullString
	err := row.Scan(&pw)
	if err != nil || !pw.Valid {
		return false, fmt.Errorf("Username '%s' does not exist", username)
	}

	if pw.String != Sha256String(password) {
		return false, fmt.Errorf("Incorrect password")
	}

	return true, nil
}

func Login(db *sql.DB, username string, password string, cookie string) (bool, error) {
	query := "SELECT password FROM users WHERE name=$1"
	row := db.QueryRow(query, username)

	var pw sql.NullString
	err := row.Scan(&pw)
	if err != nil || !pw.Valid {
		return false, fmt.Errorf("Username '%s' does not exist", username)
	}

	if pw.String != Sha256String(password) {
		return false, fmt.Errorf("Incorrect password")
	}

	// Set cookie
	query = "UPDATE users SET login_cookie=$1, login_valid=TRUE WHERE name=$2"
	_, err = db.Exec(query, cookie, username)
	if err != nil {
		return false, fmt.Errorf("Could not login, service unavailable")
	}

	return true, nil
}

func UserLoggedIn(db *sql.DB, cookie string) (bool, User) {
	query := "SELECT name, email, login_valid FROM users WHERE login_cookie=$1"
	row := db.QueryRow(query, cookie)

	var user User

	err := row.Scan(&user.Name, &user.Email, &user.LoginValid)
	if err != nil || !user.LoginValid.Bool {
		return false, User{}
	}

	return true, user
}

func UserExists(db *sql.DB, username string) bool {
	query := "SELECT id FROM users WHERE name=$1"
	row := db.QueryRow(query, username)

	var id sql.NullInt64
	err := row.Scan(&id)

	if err != nil {
		return false
	}
	return true
}

func CreateUser(db *sql.DB, username string, password string, email string) error {
	query := "INSERT INTO users (name, password, email) VALUES ($1, $2, $3)"

	pw := Sha256String(password)
	_, err := db.Exec(query, username, pw, email)

	if err != nil {
		return fmt.Errorf("Could not create user %s in the database: %v", username, err)
	}
	return nil
}

func InvalidateLogin(db *sql.DB, cookie string) error {
	query := "UPDATE users SET login_valid=FALSE WHERE login_cookie=$1"
	_, err := db.Exec(query, cookie)

	if err != nil {
		return fmt.Errorf("Could not invalidade login: %v", err)
	}
	return nil
}

func CreateRuleForUser(db *sql.DB, user User, prefix string, suffix string, length int, name string) error {
	// Check if the rule already exists
	query := `
	SELECT users.id, a.service_name, name 
	FROM users 
	LEFT JOIN 
	(
		SELECT user_id, service_name 
		FROM pattern 
		WHERE service_name=$1
	) as a 
	ON user_id=users.id
	WHERE name=$2
	`

	row := db.QueryRow(query, name, user.Name)

	var id sql.NullInt64
	var serviceName sql.NullString
	var userName sql.NullString

	err := row.Scan(&id, &serviceName, &userName)
	if err != nil {
		return fmt.Errorf("Could not find user in the database: %v %s, %s", err, name, user.Name)
	}

	if serviceName.Valid {
		return fmt.Errorf("Service rule already exists")
	}

	// If it doesn't, create it
	query = `INSERT INTO pattern 
		(user_id, service_name, length, prefix_salt, suffix_salt) 
		VALUES ($1, $2, $3, $4, $5)`
	_, err = db.Exec(query, id.Int64, name, length, prefix, suffix)

	if err != nil {
		fmt.Printf("Could not create rule in the database: %v", err)
		return fmt.Errorf("Could not create rule, service unavailable")
	}

	return nil
}

func DeleteRule(db *sql.DB, username string, svc string) error {
	// Check if the rule exists
	query := `
	SELECT users.id, a.service_name, name 
	FROM users 
	LEFT JOIN 
	(
		SELECT user_id, service_name 
		FROM pattern 
		WHERE service_name=$1
	) as a 
	ON user_id=users.id
	WHERE name=$2
	`
	row := db.QueryRow(query, svc, username)

	var id sql.NullInt64
	var userName sql.NullString
	var serviceName sql.NullString

	err := row.Scan(&id, &serviceName, &userName)
	if err != nil {
		return fmt.Errorf("Could not find user in the database")
	}

	if !serviceName.Valid {
		return fmt.Errorf("Service rule does not exist")
	}

	query = "DELETE FROM pattern WHERE service_name=$1 AND user_id=$2"
	_, err = db.Exec(query, svc, id.Int64)

	if err != nil {
		return fmt.Errorf("Could not delete service")
	}

	return nil
}

func RulesList(db *sql.DB, username string) ([]ShaPassRule, error) {
	query := `
		SELECT service_name, prefix_salt, suffix_salt, length FROM pattern 
		INNER JOIN users ON user_id=users.id WHERE name=$1
	`
	rows, err := db.Query(query, username)
	defer rows.Close()

	if err != nil {
		return nil, fmt.Errorf("Could not get rules from database")
	}

	rules := []ShaPassRule{}
	for rows.Next() {
		var serviceName sql.NullString
		var prefix sql.NullString
		var suffix sql.NullString
		var length sql.NullInt64
		err := rows.Scan(&serviceName, &prefix, &suffix, &length)
		if err != nil {
			fmt.Println("Could not scan rows")
		} else {
			rule := ShaPassRule{
				Name:   serviceName.String,
				Prefix: prefix.String,
				Suffix: suffix.String,
				Length: int(length.Int64),
			}
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

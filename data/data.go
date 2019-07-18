package data

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq" // needed to start the postgres driver
)

type ShaPassRule struct {
	ID           int
	Name         string
	Length       int
	Prefix       string
	Suffix       string
	UpdatedAt    time.Time
	UpdatedAtInt int64
}

type User struct {
	Email       sql.NullString
	Password    sql.NullString
	LoginCookie sql.NullString
	LoginValid  sql.NullBool
}

func OpenDatabase() (*sql.DB, error) {
	host := "localhost"
	port := "5555"
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

func PasswordMatches(db *sql.DB, email string, password string) (bool, error) {
	query := "SELECT password FROM users WHERE email=$1"
	row := db.QueryRow(query, email)

	var pw sql.NullString
	err := row.Scan(&pw)
	if err != nil || !pw.Valid {
		return false, fmt.Errorf("Username '%s' does not exist", email)
	}

	if bcrypt.CompareHashAndPassword([]byte(pw.String), []byte(password)) != nil {
		return false, fmt.Errorf("Incorrect password")
	}

	return true, nil
}

func Login(db *sql.DB, email string, password string, cookie string) (bool, error) {
	query := "SELECT password FROM users WHERE email=$1"
	row := db.QueryRow(query, email)

	var pw sql.NullString
	err := row.Scan(&pw)
	if err != nil || !pw.Valid {
		return false, fmt.Errorf("Username '%s' does not exist", email)
	}

	if bcrypt.CompareHashAndPassword([]byte(pw.String), []byte(password)) != nil {
		return false, fmt.Errorf("Incorrect password")
	}

	// Set cookie which is already hashed by the caller
	query = "UPDATE users SET login_cookie=$1, login_valid=TRUE WHERE email=$2"
	_, err = db.Exec(query, cookie, email)
	if err != nil {
		return false, fmt.Errorf("Could not login, service unavailable")
	}

	return true, nil
}

func UserLoggedIn(db *sql.DB, cookie string) (bool, User) {
	query := "SELECT email, login_valid, login_cookie FROM users WHERE email=$1"

	index := strings.IndexRune(cookie, ':')

	if index == -1 {
		if cookie != "" {
			fmt.Printf("Invalid login cookie format %s'...\n", cookie)
		}
		return false, User{}
	}
	email := cookie[:index]

	row := db.QueryRow(query, email)

	var user User
	err := row.Scan(&user.Email, &user.LoginValid, &user.LoginCookie)
	if err != nil || !user.LoginValid.Bool {
		return false, User{}
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.LoginCookie.String), []byte(cookie))
	if err != nil {
		fmt.Printf("Invalid login cookie '%s'...\n", email)
		return false, User{}
	}

	return true, user
}

func UserExists(db *sql.DB, email string) bool {
	query := "SELECT id FROM users WHERE email=$1"
	row := db.QueryRow(query, email)

	var id sql.NullInt64
	err := row.Scan(&id)

	if err != nil {
		return false
	}
	return true
}

func CreateUser(db *sql.DB, email string, password string) error {
	query := "INSERT INTO users (password, email) VALUES ($1, $2)"

	pw, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return fmt.Errorf("Could not create user %s in the database %v", email, err)
	}
	_, err = db.Exec(query, pw, email)

	if err != nil {
		return fmt.Errorf("Could not create user %s in the database: %v", email, err)
	}
	return nil
}

func InvalidateLogin(db *sql.DB, cookie string) error {
	logged, u := UserLoggedIn(db, cookie)
	if !logged {
		return fmt.Errorf("Could not logout, not logged in")
	}
	query := "UPDATE users SET login_valid=FALSE, login_cookie='' WHERE email=$1"
	_, err := db.Exec(query, u.Email.String)

	if err != nil {
		return fmt.Errorf("Could not invalidade login: %v", err)
	}
	return nil
}

func CreateRuleForUser(db *sql.DB, user User, prefix string, suffix string, length int, name string) error {
	// Check if the rule already exists
	query := `
	SELECT users.id, a.service_name, email
	FROM users
	LEFT JOIN
	(
		SELECT user_id, service_name 
		FROM pattern 
		WHERE service_name=$1
	) as a 
	ON user_id=users.id
	WHERE email=$2
	`

	row := db.QueryRow(query, name, user.Email)

	var id sql.NullInt64
	var serviceName sql.NullString
	var userEmail sql.NullString

	err := row.Scan(&id, &serviceName, &userEmail)
	if err != nil {
		return fmt.Errorf("Could not find user in the database: %v %s, %s", err, name, user.Email.String)
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

func DeleteRule(db *sql.DB, email string, svc string) error {
	// Check if the rule exists
	query := `
	SELECT users.id, a.service_name, email
	FROM users 
	LEFT JOIN 
	(
		SELECT user_id, service_name
		FROM pattern 
		WHERE service_name=$1
	) as a 
	ON user_id=users.id
	WHERE email=$2
	`
	row := db.QueryRow(query, svc, email)

	var id sql.NullInt64
	var userEmail sql.NullString
	var serviceName sql.NullString

	err := row.Scan(&id, &serviceName, &userEmail)
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

func RulesList(db *sql.DB, email string) ([]ShaPassRule, error) {
	query := `
		SELECT pattern.id, service_name, prefix_salt, suffix_salt, length, pattern.updated_at FROM pattern 
		INNER JOIN users ON user_id=users.id WHERE email=$1
	`
	rows, err := db.Query(query, email)
	defer rows.Close()

	if err != nil {
		return nil, fmt.Errorf("Could not get rules from database")
	}

	rules := []ShaPassRule{}
	for rows.Next() {
		var patternID sql.NullInt64
		var serviceName sql.NullString
		var prefix sql.NullString
		var suffix sql.NullString
		var length sql.NullInt64
		var updatedAt time.Time
		err := rows.Scan(&patternID, &serviceName, &prefix, &suffix, &length, &updatedAt)

		if err != nil {
			fmt.Println("Could not scan rows to fetch rule for user:", email)
		} else {
			rule := ShaPassRule{
				ID:        int(patternID.Int64),
				Name:      serviceName.String,
				Prefix:    prefix.String,
				Suffix:    suffix.String,
				Length:    int(length.Int64),
				UpdatedAt: updatedAt,
			}

			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func getUserID(db *sql.DB, email string) (int, error) {
	row := db.QueryRow("SELECT id FROM users WHERE email=$1", email)
	var id sql.NullInt64
	err := row.Scan(&id)

	if err != nil {
		fmt.Println(err)
		return 0, err
	}
	return int(id.Int64), nil
}

func SyncRules(db *sql.DB, in []ShaPassRule, email string) []error {
	retErr := []error{}
	rules, err := RulesList(db, email)
	if err != nil {
		retErr = append(retErr, fmt.Errorf("Could not sync, email %s does not exist or service is unavailable", email))
		return retErr
	}
	userID, err := getUserID(db, email)
	if err != nil {
		retErr = append(retErr, fmt.Errorf("Could not sync, username %s does not exist or service is unavailable", email))
		return retErr
	}

	// transform rules into a map
	m := make(map[string]ShaPassRule)
	for _, r := range rules {
		m[r.Name] = r
	}

	updateRules := []ShaPassRule{}
	insertRules := []ShaPassRule{}
	for _, r := range in {
		if _, ok := m[r.Name]; ok {
			// do an update

			// TODO(psv): when the timestamp format is decided
			// put this back on, for now we always update the rule
			//currentTime := m[r.Name].UpdatedAt
			//incomeTime := time.Unix(r.UpdatedAtInt, 0)
			//if incomeTime.After(currentTime) {
			// append rule here
			//}

			updateRules = append(updateRules, r)
			delete(m, r.Name)
		} else {
			// do an insert
			insertRules = append(insertRules, r)
		}
	}

	db.Exec("BEGIN TRANSACTION")

	// Update rules that already exist
	for _, u := range updateRules {
		stmt := `
			UPDATE pattern SET 
				length=$1, 
				prefix_salt=$2, 
				suffix_salt=$3
			WHERE user_id=$4 AND service_name=$5
		`
		_, err := db.Exec(stmt, u.Length, u.Prefix, u.Suffix, userID, u.Name)
		if err != nil {
			fmt.Printf("Error updating rule %s for user %s: %v\n", u.Name, email, err)
			retErr = append(retErr, fmt.Errorf("Error updating service %s", u.Name))
		}
	}

	// Insert new rules
	if len(insertRules) > 0 {
		insertStmt := `
			INSERT INTO pattern (user_id, service_name, prefix_salt, suffix_salt)
			VALUES 
		`
		var svcs []string
		var args []interface{}
		for i, rule := range insertRules {
			index := (i * 4) + 1
			insertStmt += fmt.Sprintf("($%d, $%d, $%d, $%d)", index, index+1, index+2, index+3)
			svcs = append(svcs, rule.Name)
			args = append(args, userID, rule.Name, rule.Prefix, rule.Suffix)
			if i+1 != len(insertRules) {
				insertStmt += ", "
			}
		}
		_, err := db.Exec(insertStmt, args...)
		if err != nil {
			fmt.Println("Could not insert rules in the database for user:", email, err)
			retErr = append(retErr, fmt.Errorf("Error registering services: %v", svcs))
		}
	}
	if len(retErr) == 0 {
		db.Exec("COMMIT")
	} else {
		db.Exec("ROLLBACK")
	}

	// Delete if more recent
	// 'm' map holds the entries that should be deleted
	return retErr
}

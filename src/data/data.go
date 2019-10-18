package data

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq" // needed to start the postgres driver

	"../models"
)

type ShaPassRule struct {
	ID        int
	Name      string
	Length    int
	Prefix    string
	Suffix    string
	Algorithm string
	Metadata  string `json:"Metadata,omitempty"`

	UpdatedAt    time.Time `json:"-"`
	UpdatedAtInt int64     `json:"-"`
}

type User struct {
	ID             sql.NullInt64
	Email          sql.NullString
	HashedPassword sql.NullString
	LastLogin      sql.NullString
	Activated      sql.NullBool
}

type LoginInfo struct {
	GUID      string
	CreatedAt int64
	ExpireAt  int64
	Expired   bool
	Current   bool
}

func OpenDatabase(host string, port string, password string, database string) (*sql.DB, error) {
	user := "admin"
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

func ActivateUser(db *sql.DB, email string, token string) (error, models.ErrorCode) {
	row := db.QueryRow("SELECT id FROM users WHERE email = $1 AND password_reset_token = $2 AND activated = FALSE", email, token)
	var userID sql.NullInt64
	err := row.Scan(&userID)

	if err != nil || !userID.Valid {
		return fmt.Errorf("Invalid signup token or user already activated"), models.CodeInvalidToken
	}

	query := "UPDATE users SET activated = TRUE, password_reset_token = NULL WHERE id = $1"

	_, err = db.Exec(query, userID.Int64)

	if err != nil {
		return err, models.CodeInternalError
	}
	return nil, models.CodeOK
}

func CreateUser(db *sql.DB, email string, password string, token string) (error, models.ErrorCode) {
	query := "INSERT INTO users (password, email, password_reset_token, activated) VALUES ($1, $2, $3, FALSE)"

	pw, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Printf("Could not create user %s in the database: %v", email, err)
		return fmt.Errorf("Could not create user %s in the database, unexpected error", email), models.CodeInternalError
	}
	_, err = db.Exec(query, pw, email, token)

	if err != nil {
		fmt.Printf("Could not create user %s in the database: %v\n", email, err)
		return fmt.Errorf("Could not create user %s in the database, unexpected error", email), models.CodeInternalError
	}
	return nil, models.CodeOK
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

// CheckDatabase tries to reconnect to the database when the connection
// is lost. This function is asyncronous
func CheckDatabase(db *sql.DB) {
	var connected bool
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

func Login(db *sql.DB, email string, password string, token string) (bool, error, models.ErrorCode) {
	query := "SELECT id, password, activated FROM users WHERE email=$1"
	row := db.QueryRow(query, email)

	var pw sql.NullString
	var userID sql.NullInt64
	var activated sql.NullBool
	err := row.Scan(&userID, &pw, &activated)

	if err != nil || !pw.Valid {
		return false, fmt.Errorf("User '%s' does not exist", email), models.CodeUserDoesNotExist
	}

	if !activated.Bool {
		return false, fmt.Errorf("User '%s' is not activated", email), models.CodeUserNotActivated
	}

	if bcrypt.CompareHashAndPassword([]byte(pw.String), []byte(password)) != nil {
		return false, fmt.Errorf("Incorrect password"), models.CodeIncorrectLoginInfo
	}

	// Create a login
	query = "INSERT INTO login (user_id, login_token, expire_at) VALUES ($1, $2, $3)"

	// Expire time 3 months (roughly)
	expire := time.Now().UTC().Add(time.Hour * 24 * 90)

	// Set token which is already hashed by the caller
	_, err = db.Exec(query, userID.Int64, token, expire)
	if err != nil {
		return false, fmt.Errorf("Could not login, service unavailable"), models.CodeInternalError
	}

	// Update last login
	query = "UPDATE users SET last_login=$1, login_count=login_count+1 WHERE id=$2"
	_, err = db.Exec(query, time.Now().UTC(), userID.Int64)
	if err != nil {
		fmt.Println(err)
	}

	return true, nil, models.CodeOK
}

func UserInfoFromToken(db *sql.DB, token string) (User, error) {
	query := `
	SELECT users.id, users.email, users.password, users.last_login, users.activated
	FROM login INNER JOIN users ON users.id=login.user_id
	WHERE login.login_token=$1 AND expire_at > $2`

	row := db.QueryRow(query, token, time.Now().UTC())

	var user User
	err := row.Scan(&user.ID, &user.Email, &user.HashedPassword, &user.LastLogin, &user.Activated)
	if err != nil {
		return User{}, fmt.Errorf("Not logged in")
	}

	return user, nil
}

func UserInfoFromEmail(db *sql.DB, email string) (User, error) {
	query := `
	SELECT users.id, users.email, users.password, users.last_login, users.activated
	FROM users WHERE email=$1`

	row := db.QueryRow(query, email)

	var user User
	err := row.Scan(&user.ID, &user.Email, &user.HashedPassword, &user.LastLogin, &user.Activated)
	if err != nil {
		return User{}, fmt.Errorf("User does not exist")
	}
	return user, nil
}

func RulesList(db *sql.DB, email string) ([]ShaPassRule, error) {
	query := `
		SELECT pattern.id, service_name, prefix_salt, suffix_salt, length, pattern.updated_at, algorithm, metadata FROM pattern
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
		var algorithm sql.NullString
		var metadata sql.NullString
		err := rows.Scan(&patternID, &serviceName, &prefix, &suffix, &length, &updatedAt, &algorithm, &metadata)

		if err != nil {
			fmt.Println("Could not scan rows to fetch rule for user:", email)
		} else {
			rule := ShaPassRule{
				ID:        int(patternID.Int64),
				Name:      serviceName.String,
				Prefix:    prefix.String,
				Suffix:    suffix.String,
				Length:    int(length.Int64),
				Algorithm: algorithm.String,
				Metadata:  metadata.String,

				UpdatedAt: updatedAt,
			}

			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func SaveEncryptedData(db *sql.DB, user User, data string) (error, bool, models.ErrorCode) {
	query := `
	UPDATE users SET encrypted_data = $1
	WHERE id=$2
	`

	_, err := db.Exec(query, data, user.ID.Int64)

	if err != nil {
		return fmt.Errorf("Could not update user encrypted data: %v", err), false, models.CodeInternalError
	}

	return nil, true, models.CodeOK
}

func LoadEncryptedData(db *sql.DB, user User) (error, string, models.ErrorCode) {
	query := `
	SELECT encrypted_data FROM users WHERE id=$1
	`

	row := db.QueryRow(query, user.ID.Int64)

	var data sql.NullString
	err := row.Scan(&data)

	if err != nil {
		return fmt.Errorf("Could not load user encrypted data: %v", err), "", models.CodeInternalError
	}

	return nil, data.String, models.CodeOK
}

// Return true if the rule was updated, false otherwise
// metadata must be valid JSON
func CreateRuleForUser(db *sql.DB, user User, prefix string, suffix string, length int, name string, algorithm string, metadata string) (error, bool, models.ErrorCode) {
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
		return fmt.Errorf("Could not find user in the database: %v %s, %s", err, name, user.Email.String), false, models.CodeUserDoesNotExist
	}

	if serviceName.Valid {
		// Update rule
		query = `UPDATE pattern 
		SET length=$1, prefix_salt=$2, suffix_salt=$3, algorithm=$4, metadata=$5
		WHERE service_name=$6 AND user_id=$7`
		_, err = db.Exec(query, length, prefix, suffix, algorithm, metadata, name, id.Int64)
		if err != nil {
			fmt.Printf("Could not create rule in the database: %v", err)
			return fmt.Errorf("Could not update rule, service unavailable"), false, models.CodeInternalError
		}
		return nil, true, models.CodeOK
	} else {
		// If it doesn't, create it
		query = `INSERT INTO pattern
			(user_id, service_name, length, prefix_salt, suffix_salt, algorithm, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		_, err = db.Exec(query, id.Int64, name, length, prefix, suffix, algorithm, metadata)

		if err != nil {
			fmt.Printf("Could not create rule in the database: %v", err)
			return fmt.Errorf("Could not create rule, service unavailable"), false, models.CodeInternalError
		}
		return nil, false, models.CodeOK
	}
}

func DeleteRule(db *sql.DB, email string, svc string) (error, models.ErrorCode) {
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
		return fmt.Errorf("Could not find user in the database"), models.CodeUserDoesNotExist
	}

	if !serviceName.Valid {
		return fmt.Errorf("Service rule does not exist"), models.CodeRuleDoesNotExist
	}

	query = "DELETE FROM pattern WHERE service_name=$1 AND user_id=$2"
	_, err = db.Exec(query, svc, id.Int64)

	if err != nil {
		return fmt.Errorf("Could not delete service"), models.CodeInternalError
	}

	return nil, models.CodeOK
}

func LogoutToken(db *sql.DB, hashedToken string) error {
	query := "DELETE FROM login WHERE login_token=$1"

	_, err := db.Exec(query, hashedToken)
	if err != nil {
		return fmt.Errorf("Logout failed: %v", err)
	}

	return nil
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

func DeleteAllRulesFromUser(db *sql.DB, userID int64) error {
	query := "DELETE FROM pattern WHERE user_id=$1"
	_, err := db.Exec(query, userID)
	if err != nil {
		return err
	}
	return nil
}

func DeleteAllLoginsFromUser(db *sql.DB, userID int64) error {
	query := "DELETE FROM login WHERE user_id=$1"

	_, err := db.Exec(query, userID)

	if err != nil {
		return err
	}
	return nil
}

func DeleteUser(db *sql.DB, userID int64) error {
	query := "DELETE FROM users WHERE id=$1"
	_, err := db.Exec(query, userID)
	if err != nil {
		return err
	}
	return nil
}

func SavePasswordResetToken(db *sql.DB, email string, hashedToken string) (error, models.ErrorCode) {
	query := "SELECT id, last_password_reset_time, activated FROM users WHERE email=$1"

	row := db.QueryRow(query, email)

	var userID sql.NullInt64
	var lastPwResetTime sql.NullString
	var activated sql.NullBool

	err := row.Scan(&userID, &lastPwResetTime, &activated)
	if err != nil {
		fmt.Println(err)
		return fmt.Errorf("User does not exist"), models.CodeUserDoesNotExist
	}

	if !activated.Bool {
		return fmt.Errorf("User not activated"), models.CodeUserNotActivated
	}

	if lastPwResetTime.Valid {
		// Check to see if 30 minutes have passed, only allow
		// A password reset every 30 minutes
		t, err := time.Parse(time.RFC3339, lastPwResetTime.String)
		if err != nil {
			fmt.Println("Could not parse timestamp: ", err)
			return fmt.Errorf("Cannot reset password, unexpected error"), models.CodeInternalError
		}

		duration := time.Minute * 30
		timeAllow := (t.Add(duration)).Before(time.Now().UTC())

		if !timeAllow {
			// Cannot reset password yet
			return fmt.Errorf("Can only reset password every 30min, (elapsed: %v)", time.Now().UTC().Sub(t)), models.CodeResetPasswordDelay
		}
	}

	// Set it
	query = `
	UPDATE users 
	SET last_password_reset_time=$1, password_reset_token=$2
	WHERE id=$3`
	_, err = db.Exec(query, time.Now().UTC(), hashedToken, userID.Int64)
	if err != nil {
		return fmt.Errorf("Could not reset password, unexpected error"), models.CodeInternalError
	}

	return nil, models.CodeOK
}

func ResetPassword(db *sql.DB, newPassword string, email string, hashedToken string) (error, models.ErrorCode) {
	query := `
	UPDATE users 
	SET password=$1, last_password_reset_time=$2, password_reset_token=NULL
	WHERE email=$3 AND password_reset_token=$4`

	res, err := db.Exec(query, newPassword, time.Now().UTC(), email, hashedToken)
	rowsAffected, _ := res.RowsAffected()

	if err != nil {
		return fmt.Errorf("Could not reset password, unexpected error"), models.CodeInternalError
	}
	if rowsAffected != 1 {
		return fmt.Errorf("Could not reset password, invalid token for email"), models.CodeInvalidToken
	}

	return nil, models.CodeOK
}

// ListLogin returns information on all logins made by the userID specified
//
// - 'currentHashedToken' is compared with every token and when a match is found, the field
//   Current in the login info is set to indicate that login as the currently used in this API call.
//
// - 'returnExpired' if set causes all logins to be returned, even when expired, otherwise
//   expired logins are not included in the response.
//
func ListLogin(db *sql.DB, userID int64, currentHashedToken string, returnExpired bool) ([]LoginInfo, error) {
	query := `
	SELECT guid, created_at, expire_at, login_token
	FROM login
	WHERE user_id=$1
	`
	rows, err := db.Query(query, userID)
	if err != nil {
		return nil, nil
	}

	var list []LoginInfo

	for rows.Next() {
		var l LoginInfo

		var createdAt time.Time
		var guid sql.NullString
		var expireAt time.Time
		var token sql.NullString
		err := rows.Scan(&guid, &createdAt, &expireAt, &token)
		if err != nil {
			fmt.Println(err)
		} else {
			expired := expireAt.Before(time.Now().UTC())

			l.CreatedAt = createdAt.UnixNano() / 1000000
			l.ExpireAt = expireAt.UnixNano() / 1000000
			l.Expired = expired
			l.GUID = guid.String

			if currentHashedToken == token.String {
				l.Current = true
			}

			if returnExpired || !expired {
				list = append(list, l)
			}
		}
	}
	return list, nil
}

func DeleteLoginTokens(db *sql.DB, userID int64, guids []string) error {
	if len(guids) <= 0 {
		return fmt.Errorf("No logins were expired")
	}
	query := "DELETE FROM login WHERE user_id = $1 AND guid IN ("

	var args []interface{}
	args = append(args, userID)

	for i, g := range guids {
		if i > 0 {
			query += ", "
		}
		query += fmt.Sprintf("$%d", i+2) // start at 2 since email is the 1st argument
		args = append(args, g)
	}

	query += ")"

	_, err := db.Exec(query, args...)

	if err != nil {
		fmt.Println("Could not expire logins, unexpected error:", err)
		return fmt.Errorf("Could not expire logins, unexpected error")
	}

	return nil
}

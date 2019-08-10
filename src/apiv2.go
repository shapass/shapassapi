package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	d "./data"
	"./mail"
	"./models"
)

type APIStatus string

const StatusOK APIStatus = "OK"
const StatusError APIStatus = "ERROR"

type APIResponse struct {
	Status  string
	Message string
}

func LogAndRespond(w http.ResponseWriter, status APIStatus, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APIResponse{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
	}
	bytes, _ := json.Marshal(&r)

	fmt.Fprintf(w, string(bytes))
}

type APIListResponse struct {
	Status  string
	Message string
	Rules   []d.ShaPassRule
}

func LogAndRespondList(w http.ResponseWriter, status APIStatus, rules []d.ShaPassRule, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APIListResponse{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Rules:   rules,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

type APILoginResponse struct {
	Status  string
	Message string
	Token   string
}

func LogAndRespondLogin(w http.ResponseWriter, status APIStatus, token string, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APILoginResponse{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Token:   token,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

type APILoginListResponse struct {
	Status    string
	Message   string
	LoginList []d.LoginInfo
}

func LogAndRespondListLogin(w http.ResponseWriter, status APIStatus, logins []d.LoginInfo, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APILoginListResponse{
		Status:    string(status),
		Message:   fmt.Sprintf(message, args...),
		LoginList: logins,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

func getLoginInfo(email, password, token string) (d.User, error) {
	if token != "" {
		// Try token
		hashedToken := sha256.Sum256([]byte(token))
		return d.UserInfoFromToken(db, hex.EncodeToString(hashedToken[:]))
	} else if email != "" && password != "" {
		// Try with email and password
		user, err := d.UserInfoFromEmail(db, email)
		if err != nil {
			return d.User{}, err
		}
		// Check if password is correct
		if bcrypt.CompareHashAndPassword([]byte(user.HashedPassword.String), []byte(password)) != nil {
			return d.User{}, fmt.Errorf("Incorrect password")
		}
		return user, nil
	} else {
		return d.User{}, fmt.Errorf("Not logged in")
	}
}

// HandleSignUpV2 does the signing up process, only if the email provided
// does not already exist
func HandleSignUpV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APISignUp
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not sign up: invalid json data")
		return
	}

	// Check validity of fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, "Could not sign up: email and password are required")
		return
	}

	// Check if user already exist
	if d.UserExists(db, info.Email) {
		LogAndRespond(w, StatusError, "User '%s' already exists", info.Email)
		return
	}

	// Register user in the database
	err = d.CreateUser(db, info.Email, info.Password)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "User '%s' signed up successfully!", info.Email)
}

func HandleLoginV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.UserInfo
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not login: invalid json data")
		return
	}

	// Check validity of fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, "Could not login: email and password are required")
		return
	}

	// String that will be the login token is always 64 bytes long
	// The final token will be encoded in base64, therefore it will contain 88 bytes
	randStr, err := GenerateRandomString(64)
	if err != nil {
		LogAndRespond(w, StatusError, "Error trying to login")
		return
	}

	// Hash the token to be saved in the database
	hashedToken := sha256.Sum256([]byte(randStr))
	_, err = d.Login(db, info.Email, info.Password, hex.EncodeToString(hashedToken[:]))

	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	//LogAndRespond(w, StatusOK, "User '%s' logged in successfully!", info.Email)
	LogAndRespondLogin(w, StatusOK, randStr, "User '%s' logged in successfully!", info.Email)
}

func HandleListV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIList
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not list: invalid json data")
		return
	}

	// Login info
	user, err := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	rules, err := d.RulesList(db, user.Email.String)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespondList(w, StatusOK, rules, "Rules successfully fetched for user '%s'", user.Email.String)
}

func HandleCreateV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APICreate
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not create: invalid json data")
		return
	}

	// Check required fields
	if info.Name == "" {
		LogAndRespond(w, StatusError, "Create requires name field")
		return
	}

	// length 32 is default, override if 0 is provided
	if info.Length == 0 {
		info.Length = 32
	}

	// Length must be 64 characters max
	if len(info.Name) > 64 {
		LogAndRespond(w, StatusError, "Service name max length is 64 characters")
		return
	}

	// If metadata is null, assume empty JSON object
	if info.Metadata == "" {
		info.Metadata = "{}"
	}

	// Error if not JSON
	if !IsJSON(info.Metadata) {
		LogAndRespond(w, StatusError, "metadata field is not valid JSON")
		return
	}

	maxMetadataLength := 8192
	if len(info.Metadata) > maxMetadataLength {
		LogAndRespond(w, StatusError, "metadata field is too large, max is %d bytes", maxMetadataLength)
		return
	}

	// Check valid algorithms
	switch info.Algorithm {
	case "sha256-str":
	case "sha256-bin":
	case "sha256-bin-alfanum":
	case "":
		info.Algorithm = "sha256-str"
	default:
		LogAndRespond(w, StatusError, "Invalid algorithm '%s'", info.Algorithm)
		return
	}

	// Login info
	user, err := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
	}

	err, updated := d.CreateRuleForUser(db, user, info.Prefix, info.Suffix, info.Length, info.Name, info.Algorithm, info.Metadata)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	if updated {
		LogAndRespond(w, StatusOK, "Updated rule successfully!")
	} else {
		LogAndRespond(w, StatusOK, "Created rule successfully!")
	}
}

func HandleWhoAmIV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIWhoAmI
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Whoami failed: invalid json data")
		return
	}

	// Login info
	user, err := getLoginInfo("", "", info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "%s", user.Email.String)
}

func HandleDeleteV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIDelete
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not delete rule: invalid json data")
		return
	}

	// Check validity of fields
	if info.Name == "" {
		LogAndRespond(w, StatusError, "Name of rule to be deleted must be provided")
		return
	}

	// Login info
	user, err := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	// Delete the rule in the database
	err = d.DeleteRule(db, user.Email.String, info.Name)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "Deleted successfully!")
}

func HandleLogoutV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILogout
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not logout: invalid json data")
		return
	}

	user, err := getLoginInfo("", "", info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	hashedToken := sha256.Sum256([]byte(info.Token))
	err = d.LogoutToken(db, hex.EncodeToString(hashedToken[:]))
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "User '%s' logout successfully!", user.Email.String)
}

func HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIDeleteAccount
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not delete account: invalid json data")
		return
	}

	// Check required fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, "Could not delete account, email and password are required")
		return
	}

	user, err := getLoginInfo(info.Email, info.Password, "")
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	// Delete account
	err = d.DeleteAllRulesFromUser(db, user.ID.Int64)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not delete account, unexpected error occurred")
		fmt.Println(err)
	}

	err = d.DeleteUser(db, user.ID.Int64)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not delete account, unexpected error occurred")
		fmt.Println(err)
	}

	LogAndRespond(w, StatusOK, "Deleted user '%s' successfully!", user.Email.String)
}

func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIResetPassword
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not delete account: invalid json data")
		return
	}

	// Check if fields are valid
	if info.Email == "" {
		LogAndRespond(w, StatusError, "Could not reset password, email is required")
		return
	}

	if info.Token == "" {
		// Stage 1, send token by email and save it to the database hashed
		resetToken, err := GenerateRandomString(64)
		if err != nil {
			LogAndRespond(w, StatusError, "Password reset failed: unexpected error")
			return
		}
		hashedToken := sha256.Sum256([]byte(resetToken))
		err = d.SavePasswordResetToken(db, info.Email, hex.EncodeToString(hashedToken[:]))
		if err != nil {
			LogAndRespond(w, StatusError, "Password reset failed: %v", err)
			return
		}

		err = mail.SendMailToUser(globalEmail, info.Email, globalEmailPassword, "Reset Password",
			fmt.Sprintf("To reset your password access: %s?token=%s", globalShapassResetLink, resetToken))

		if err != nil {
			fmt.Println(err)
			LogAndRespond(w, StatusError, "We could not send reset email, try again later")
			return
		}

		LogAndRespond(w, StatusOK, "Password reset request successful, check your email")
	} else {
		// Stage 2, really reset password
		if info.NewPassword == "" {
			LogAndRespond(w, StatusError, "Reset password failed: new password is required and cannot be empty")
			return
		}

		// Require reset token
		if info.Token == "" {
			LogAndRespond(w, StatusError, "Reset password failed: token must be provided")
			return
		}

		hashedToken := sha256.Sum256([]byte(info.Token))
		hashedPw, err := bcrypt.GenerateFromPassword([]byte(info.NewPassword), 10)
		if err != nil {
			LogAndRespond(w, StatusError, "Reset password failed: could not hash password")
			return
		}

		err = d.ResetPassword(db, string(hashedPw), info.Email, hex.EncodeToString(hashedToken[:]))
		if err != nil {
			LogAndRespond(w, StatusError, "%v", err)
			return
		}

		LogAndRespond(w, StatusOK, "Password reset successfully!")
	}
}

func HandleLoginList(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILoginList
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not list logins: invalid json data")
		return
	}

	// Login info
	user, err := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	hashedToken := ""
	if info.Token != "" {
		h := sha256.Sum256([]byte(info.Token))
		hashedToken = hex.EncodeToString(h[:])
	}

	list, _ := d.ListLogin(db, user.ID.Int64, hashedToken, info.All)

	LogAndRespondListLogin(w, StatusOK, list, "Login list fetched successfully!")
}

func HandleLoginExpire(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILoginExpire
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, "Could not expire logins: invalid json data")
		return
	}

	// Check required fields
	if len(info.GUIDs) <= 0 {
		LogAndRespond(w, StatusError, "No guids were provided")
		return
	}

	// Login info
	user, err := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	// Delete in the database
	err = d.DeleteLoginTokens(db, user.ID.Int64, info.GUIDs)
	if err != nil {
		LogAndRespond(w, StatusError, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, "Deleted logins successfully!")
}

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
	Code    models.ErrorCode
}

func LogAndRespond(w http.ResponseWriter, status APIStatus, code models.ErrorCode, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APIResponse{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Code:    code,
	}
	bytes, _ := json.Marshal(&r)

	fmt.Fprintf(w, string(bytes))
}

type APIListResponse struct {
	Status  string
	Message string
	Rules   []d.ShaPassRule
	Code    models.ErrorCode
}

func LogAndRespondList(w http.ResponseWriter, status APIStatus, code models.ErrorCode, rules []d.ShaPassRule, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APIListResponse{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Rules:   rules,
		Code:    code,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

type APILoginResponse struct {
	Status     string
	Message    string
	Token      string
	LoginCount int64
	Code       models.ErrorCode
}

func LogAndRespondLogin(w http.ResponseWriter, status APIStatus, code models.ErrorCode, token string, loginCount int64, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APILoginResponse{
		Status:     string(status),
		Message:    fmt.Sprintf(message, args...),
		Token:      token,
		Code:       code,
		LoginCount: loginCount,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

type APILoginListResponse struct {
	Status    string
	Message   string
	LoginList []d.LoginInfo
}

func LogAndRespondListLogin(w http.ResponseWriter, status APIStatus, code models.ErrorCode, logins []d.LoginInfo, message string, args ...interface{}) {
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

type APILoadResponse struct {
	Status        string
	Message       string
	EncryptedData string
}

func LogAndRespondLoad(w http.ResponseWriter, status APIStatus, code models.ErrorCode, encryptedData, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APILoadResponse{
		Status:        string(status),
		Message:       fmt.Sprintf(message, args...),
		EncryptedData: encryptedData,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

func getLoginInfo(email, password, token string) (d.User, error, models.ErrorCode) {
	if token != "" {
		// Try token
		hashedToken := sha256.Sum256([]byte(token))
		user, err := d.UserInfoFromToken(db, hex.EncodeToString(hashedToken[:]))
		if err == nil && !user.Activated.Bool {
			return d.User{}, fmt.Errorf("User not activated"), models.CodeUserNotActivated
		}
		return user, err, models.CodeNotLoggedIn
	} else if email != "" && password != "" {
		// Try with email and password
		user, err := d.UserInfoFromEmail(db, email)
		if err != nil {
			// TODO(psv): Log user not exist
			return d.User{}, err, models.CodeIncorrectLoginInfo
		}
		// Check if password is correct
		if bcrypt.CompareHashAndPassword([]byte(user.HashedPassword.String), []byte(password)) != nil {
			return d.User{}, fmt.Errorf("Incorrect password"), models.CodeIncorrectLoginInfo
		}

		if !user.Activated.Bool {
			return d.User{}, fmt.Errorf("User not activated"), models.CodeUserNotActivated
		}
		return user, nil, models.CodeOK
	} else {
		return d.User{}, fmt.Errorf("Not logged in"), models.CodeNotLoggedIn
	}
}

func HandleSignUpConfirmation(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.Form.Get("email")
	token := r.Form.Get("token")

	if email == "" || token == "" {
		codeStr := models.ErrorCode(models.CodeIncorrectSignupInfo).String()
		fmt.Printf("Could not confirm signup, email and token are required\n3")
		http.Redirect(w, r, globalShapassConfirmationPath+"?email="+email+"&confirmed=false&code="+codeStr, 301)
		return
	}

	t := sha256.Sum256([]byte(token))
	hashedToken := hex.EncodeToString(t[:])

	err, errCode := d.ActivateUser(db, email, hashedToken)
	if err != nil {
		fmt.Printf("Could not confirm signup for '%s': %v\n", email, err)
		http.Redirect(w, r, globalShapassConfirmationPath+"?email="+email+"&confirmed=false&code="+errCode.String(), 301)
		return
	}

	http.Redirect(w, r, globalShapassConfirmationPath+"?email="+email+"&confirmed=true", 301)
}

// HandleSignUpV2 does the signing up process, only if the email provided
// does not already exist
func HandleSignUpV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APISignUp
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not sign up: invalid json data")
		return
	}

	// Check validity of fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, models.CodeIncorrectSignupInfo, "Could not sign up: email and password are required")
		return
	}

	// Check if user already exist
	if d.UserExists(db, info.Email) {
		LogAndRespond(w, StatusError, models.CodeIncorrectSignupInfo, "User '%s' already exists", info.Email)
		return
	}

	// First stage, send token to the user email
	signupToken, err := GenerateRandomString(64)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "Signup failed: unexpected error")
		return
	}
	token := sha256.Sum256([]byte(signupToken))
	hashedToken := hex.EncodeToString(token[:])

	// Register user in the database, not activated
	err, errCode := d.CreateUser(db, info.Email, info.Password, hashedToken)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	// Registered successfully, send email
	msg := fmt.Sprintf("To confirm your account please click the link: %s?email=%s&token=%s", globalShapassSignupPath, info.Email, signupToken)
	err = mail.SendMailToUser(globalEmail, info.Email, globalEmailPassword, "Sign up to shapass", msg)

	if err != nil {
		fmt.Printf("We could not sign signup email for user '%s': %v\n", info.Email, err)
		LogAndRespond(w, StatusError, models.CodeCouldNotSendEmail, "We could not send signup email, try again later")
		return
	}

	fmt.Printf("User '%s' signed up! Email sent\n", info.Email)
	LogAndRespond(w, StatusOK, models.CodeOK, "Sent confirmation email to '%s' successfully!", info.Email)
}

func resendConfirmationEmail(info models.UserInfo) error {
	// Create another token
	signupToken, err := GenerateRandomString(64)
	if err != nil {
		return err
	}
	token := sha256.Sum256([]byte(signupToken))
	hashedToken := hex.EncodeToString(token[:])

	match, _ := d.PasswordMatches(db, info.Email, info.Password)
	if match {
		err, _ = d.UpdateSignupToken(db, info.Email, hashedToken)
		if err != nil {
			return err
		}
		// Registered successfully, send email
		msg := fmt.Sprintf("To confirm your account please click the link: %s?email=%s&token=%s", globalShapassSignupPath, info.Email, signupToken)
		err = mail.SendMailToUser(globalEmail, info.Email, globalEmailPassword, "Resent shapass verification", msg)
		return nil
	} else {
		return fmt.Errorf("User information is incorrect")
	}
}

func HandleLoginV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.UserInfo
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not login: invalid json data")
		return
	}

	// Check validity of fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, models.CodeIncorrectLoginInfo, "Could not login: email and password are required")
		return
	}

	// String that will be the login token is always 64 bytes long
	// The final token will be encoded in base64, therefore it will contain 88 bytes
	randStr, err := GenerateRandomString(64)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "%v", err)
		return
	}

	// Hash the token to be saved in the database
	hashedToken := sha256.Sum256([]byte(randStr))
	_, err, errCode, loginCount := d.Login(db, info.Email, info.Password, hex.EncodeToString(hashedToken[:]))

	if err != nil {
		if errCode == models.CodeUserNotActivated {
			// Send confirmation email again
			resendConfirmationEmail(info)
		}
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	LogAndRespondLogin(w, StatusOK, models.CodeOK, randStr, loginCount, "User '%s' logged in successfully!", info.Email)
}

func HandleListV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIList
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not list: invalid json data")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	rules, err := d.RulesList(db, user.Email.String)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "%v", err)
		return
	}

	LogAndRespondList(w, StatusOK, models.CodeOK, rules, "Rules successfully fetched for user '%s'", user.Email.String)
}

func HandleCreateV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APICreate
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not create: invalid json data")
		return
	}

	// Check required fields
	if info.Name == "" {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Create requires name field")
		return
	}

	// length 32 is default, override if 0 is provided
	if info.Length == 0 {
		info.Length = 32
	}

	// Length must be 64 characters max
	if len(info.Name) > 64 {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Service name max length is 64 characters")
		return
	}

	// If metadata is null, assume empty JSON object
	if info.Metadata == "" {
		info.Metadata = "{}"
	}

	// Error if not JSON
	if !IsJSON(info.Metadata) {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "metadata field is not valid JSON")
		return
	}

	maxMetadataLength := 8192
	if len(info.Metadata) > maxMetadataLength {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "metadata field is too large, max is %d bytes", maxMetadataLength)
		return
	}

	// Check valid algorithms
	switch info.Algorithm {
	case "sha256-str":
	case "sha256-bin":
	case "sha256-bin-alphanum":
	case "":
		info.Algorithm = "sha256-str"
	default:
		LogAndRespond(w, StatusError, models.CodeInvalidAlgorithm, "Invalid algorithm '%s'", info.Algorithm)
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	err, updated, errCode := d.CreateRuleForUser(db, user, info.Prefix, info.Suffix, info.Length, info.Name, info.Algorithm, info.Metadata)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	if updated {
		LogAndRespond(w, StatusOK, models.CodeOK, "Updated rule successfully!")
	} else {
		LogAndRespond(w, StatusOK, models.CodeOK, "Created rule successfully!")
	}
}

func HandleWhoAmIV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIWhoAmI
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Whoami failed: invalid json data")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo("", "", info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "%s", user.Email.String)
}

func HandleDeleteV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIDelete
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not delete rule: invalid json data")
		return
	}

	// Check validity of fields
	if info.Name == "" {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Name of rule to be deleted must be provided")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	// Delete the rule in the database
	err, errCode = d.DeleteRule(db, user.Email.String, info.Name)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "Deleted successfully!")
}

func HandleLogoutV2(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILogout
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not logout: invalid json data")
		return
	}

	user, err, errCode := getLoginInfo("", "", info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	hashedToken := sha256.Sum256([]byte(info.Token))
	err = d.LogoutToken(db, hex.EncodeToString(hashedToken[:]))
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidToken, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "User '%s' logout successfully!", user.Email.String)
}

func HandleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIDeleteAccount
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not delete account: invalid json data")
		return
	}

	// Check required fields
	if info.Email == "" || info.Password == "" {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not delete account, email and password are required")
		return
	}

	user, err, errCode := getLoginInfo(info.Email, info.Password, "")
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	// Delete account
	err = d.DeleteAllRulesFromUser(db, user.ID.Int64)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "Could not delete account, unexpected error occurred")
		fmt.Println(err)
		return
	}

	err = d.DeleteAllLoginsFromUser(db, user.ID.Int64)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "Could not delete account, unexpected error occurred")
		fmt.Println(err)
		return
	}

	err = d.DeleteUser(db, user.ID.Int64)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInternalError, "Could not delete account, unexpected error occurred")
		fmt.Println(err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "Deleted user '%s' successfully!", user.Email.String)
}

func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APIResetPassword
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not delete account: invalid json data")
		return
	}

	// Check if fields are valid
	if info.Email == "" {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not reset password, email is required")
		return
	}

	if info.Token == "" {
		// Stage 1, send token by email and save it to the database hashed
		resetToken, err := GenerateRandomString(64)
		if err != nil {
			LogAndRespond(w, StatusError, models.CodeInternalError, "Password reset failed: unexpected error")
			return
		}
		hashedToken := sha256.Sum256([]byte(resetToken))
		err, errCode := d.SavePasswordResetToken(db, info.Email, hex.EncodeToString(hashedToken[:]))
		if err != nil {
			LogAndRespond(w, StatusError, errCode, "Password reset failed: Invalid data")
			return
		}

		err = mail.SendMailToUser(globalEmail, info.Email, globalEmailPassword, "Reset Password",
			fmt.Sprintf("To reset your password access: %s?t=%s&email=%s", globalShapassResetLink, resetToken, info.Email))

		if err != nil {
			fmt.Println(err)
			LogAndRespond(w, StatusError, models.CodeCouldNotSendEmail, "We could not send reset email, try again later")
			return
		}

		LogAndRespond(w, StatusOK, models.CodeOK, "Password reset request successful, check your email")
	} else {
		// Stage 2, really reset password
		if info.NewPassword == "" {
			LogAndRespond(w, StatusError, models.CodeInvalidInput, "Reset password failed: new password is required and cannot be empty")
			return
		}

		// Require reset token
		if info.Token == "" {
			LogAndRespond(w, StatusError, models.CodeInvalidInput, "Reset password failed: token must be provided")
			return
		}

		hashedToken := sha256.Sum256([]byte(info.Token))
		hashedPw, err := bcrypt.GenerateFromPassword([]byte(info.NewPassword), 10)
		if err != nil {
			LogAndRespond(w, StatusError, models.CodeInternalError, "Reset password failed: could not hash password")
			return
		}

		err, errCode := d.ResetPassword(db, string(hashedPw), info.Email, hex.EncodeToString(hashedToken[:]))
		if err != nil {
			LogAndRespond(w, StatusError, errCode, "%v", err)
			return
		}

		LogAndRespond(w, StatusOK, models.CodeOK, "Password reset successfully!")
		//http.Redirect(w, r, globalShapassConfirmationPath+"?email="+email+"&confirmed=true", 301)
	}
}

func HandleLoginList(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILoginList
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not list logins: invalid json data")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	hashedToken := ""
	if info.Token != "" {
		h := sha256.Sum256([]byte(info.Token))
		hashedToken = hex.EncodeToString(h[:])
	}

	list, err := d.ListLogin(db, user.ID.Int64, hashedToken, info.All)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeOK, "%v", err)
		return
	}

	LogAndRespondListLogin(w, StatusOK, models.CodeOK, list, "Login list fetched successfully!")
}

func HandleLoginExpire(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APILoginExpire
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not expire logins: invalid json data")
		return
	}

	// Check required fields
	if len(info.GUIDs) <= 0 {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "No guids were provided")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	// Delete in the database
	err = d.DeleteLoginTokens(db, user.ID.Int64, info.GUIDs)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeOK, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "Deleted logins successfully!")
}

func HandleSave(w http.ResponseWriter, r *http.Request) {
	// Read and parse the body
	var info models.APISave
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not create: invalid json data")
		return
	}

	// Check required fields
	if info.Data == "" {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Saving requires data field")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	err, _, errCode = d.SaveEncryptedData(db, user, info.Data)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "Saved encrypted data successfully!")
}

func HandleLoad(w http.ResponseWriter, r *http.Request) {
	var info models.APILoad
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not create: invalid json data")
		return
	}

	// Login info
	user, err, errCode := getLoginInfo(info.Email, info.Password, info.Token)
	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	err, encrData, errCode := d.LoadEncryptedData(db, user)

	if err != nil {
		LogAndRespond(w, StatusError, errCode, "%v", err)
		return
	}

	LogAndRespondLoad(w, StatusOK, models.CodeOK, encrData, "Load encrypted data successfully!")
}

func ResendSignupVerificationEmail(w http.ResponseWriter, r *http.Request) {
	var info models.UserInfo
	body, _ := ioutil.ReadAll(r.Body)
	err := json.Unmarshal(body, &info)
	if err != nil {
		LogAndRespond(w, StatusError, models.CodeInvalidInput, "Could not resend verification: invalid json data")
		return
	}

	u, err := d.UserInfoFromEmail(db, info.Email)
	if u.Activated.Bool {
		LogAndRespond(w, StatusError, models.CodeCouldNotSendEmail, "User already activated")
		return
	}

	err = resendConfirmationEmail(info)

	if err != nil {
		LogAndRespond(w, StatusError, models.CodeCouldNotSendEmail, "Could not resend verification email: %v", err)
		return
	}

	LogAndRespond(w, StatusOK, models.CodeOK, "Resent verification email successfully!")
}

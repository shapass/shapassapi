package models

type UserInfo struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type APILoginInfo struct {
	UserInfo
	Token string `json:"token"`
}

type APISignUp struct {
	UserInfo
}

type APIDeleteAccount struct {
	UserInfo
}

type APIWhoAmI struct {
	Token string `json:"token"`
}

type APILogout struct {
	Token string `json:"token"`
}

type APISave struct {
	APILoginInfo
	Data string `json:"data"`
}

type APILoad struct {
	APILoginInfo
}

type APICreate struct {
	APILoginInfo
	Name      string `json:"name"`
	Length    int    `json:"length"`
	Suffix    string `json:"suffix"`
	Prefix    string `json:"prefix"`
	Metadata  string `json:"metadata"`
	Algorithm string `json:"algorithm"`
}

type APIList struct {
	APILoginInfo
}

type APIDelete struct {
	APILoginInfo
	Name string `json:"name"`
}

type APIResetPassword struct {
	Email string `json:"email"`

	Token       string `json:"token"`
	NewPassword string `json:"newpassword"`
}

type APILoginList struct {
	APILoginInfo
	All bool `json:"all"`
}

type APILoginExpire struct {
	APILoginInfo
	GUIDs []string `json:"guids"`
}

// Error Codes

type ErrorCode int

const (
	// No errors occurred
	CodeOK = iota

	// An unknown error occurred (database issue mostly)
	CodeInternalError

	// The API call requires the user to be logged in and
	// the user is not.
	CodeNotLoggedIn

	// Incorrect information for login was provided.
	CodeIncorrectLoginInfo

	// Some of the fields required for signup were not
	// provided
	CodeIncorrectSignupInfo

	// The API call requires an activated user, but
	// the user info provided is from a user not yet
	// confirmed by email.
	// This error code should probably not be external.
	CodeUserNotActivated

	// User does not exist in the database.
	// This should never be raised, since the user
	// must be logged in already for an API call
	// to try to access data from them.
	CodeUserDoesNotExist

	// This error is raised when trying to delete a rule
	// that doesn't exist.
	CodeRuleDoesNotExist

	// This error is raised if the JSON input is not
	// valid JSON, or when not all fields required for
	// the called API call were provided.
	CodeInvalidInput

	// This error is raised when the token provided
	// for the API call is not valid.
	CodeInvalidToken

	// This error is raised when the email service
	// failed to send an email. User must try later.
	CodeCouldNotSendEmail

	// An invalid algorithm was sent (i.e. sha233-bin)
	CodeInvalidAlgorithm

	// The password recovery system can only be
	// issued again after some time (30m by default).
	// This error is caused by trying to reset the
	// password again before this period.
	CodeResetPasswordDelay

	// An API request was received with a method
	// different from POST.
	CodeInvalidMethod

	// Generic user error, could not access user information
	// either the user is not activated or not even registered.
	CodeUserError
)

func (e ErrorCode) String() string {
	switch e {
	case CodeOK:
		return "OK"
	case CodeInternalError:
		return "InternalError"
	case CodeNotLoggedIn:
		return "NotLoggedIn"
	case CodeIncorrectLoginInfo:
		return "IncorrectLoginInfo"
	case CodeIncorrectSignupInfo:
		return "IncorrectSignupInfo"
	case CodeUserNotActivated:
		return "UserNotActivated"
	case CodeUserDoesNotExist:
		return "UserDoesNotExist"
	case CodeRuleDoesNotExist:
		return "RuleDoesNotExist"
	case CodeInvalidInput:
		return "InvalidInput"
	case CodeInvalidToken:
		return "InvalidToken"
	case CodeCouldNotSendEmail:
		return "CouldNotSendEmail"
	case CodeInvalidAlgorithm:
		return "InvalidAlgorithm"
	case CodeResetPasswordDelay:
		return "ResetPasswordDelay"
	case CodeInvalidMethod:
		return "InvalidMethod"
	default:
		return "InvalidErrorCode"
	}
}

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

type APICreate struct {
	APILoginInfo
	Name   string `json:"name"`
	Length int    `json:"length"`
	Suffix string `json:"suffix"`
	Prefix string `json:"prefix"`
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

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"./data"
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

type APIList struct {
	Status  string
	Message string
	Rules   []data.ShaPassRule
}

func LogAndRespondList(w http.ResponseWriter, status APIStatus, rules []data.ShaPassRule, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APIList{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Rules:   rules,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

type APILogin struct {
	Status  string
	Message string
	Token   string
}

func LogAndRespondLogin(w http.ResponseWriter, status APIStatus, token string, message string, args ...interface{}) {
	fmt.Printf(message, args...)
	fmt.Printf("\n")

	r := APILogin{
		Status:  string(status),
		Message: fmt.Sprintf(message, args...),
		Token:   token,
	}

	bytes, _ := json.Marshal(&r)
	fmt.Fprintf(w, string(bytes))
}

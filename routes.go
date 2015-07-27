package main

import (
	"encoding/json"
	"fmt"
	"github.com/mrvdot/golang-utils"
	newappengine "google.golang.org/appengine"
	newdatastore "google.golang.org/appengine/datastore"
	"net/http"
	"strconv"
)

/**
TODO: Abstract 'Model' Handlers to accept interface{} argument and return Model objects of the type of that interface
*/

/** Root Handler **/
func RootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ready recipe")
}

/** User Handlers **/
func UsersHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	users := make([]User, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("User").GetAll(ctx, &users); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve users from datastore", response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, UserSuccessFetch, users, response, out)
		}
	} else {
		user := make([]User, 0, 1)
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("User").Filter("ID =", num).Limit(1).GetAll(ctx, &user); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve account with id: %s", id), response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved user with id: %s", id), user, response, out)
		}
	}
}

/** Account Handlers **/
func AccountsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	accounts := make([]Account, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("Account").GetAll(ctx, &accounts); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve accounts from datastore", response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, "dale got all accounts", accounts, response, out)
		}
	} else {
		account := make([]User, 0, 1)
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("Account").Filter("ID =", num).Limit(1).GetAll(ctx, &account); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve account with id: %s", id), response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved account with id: %s", id), account, response, out)
		}
	}
}

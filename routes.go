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
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve account with id: %s \nError: %s", id, err.Error()), response, out)
		} else {
			if len(user) > 0 {
				if acc, aErr := GetAccountFromUser(&user[0], r); aErr != nil {
					ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve account with id: %s \nError: %s", id, err.Error()), response, out)
				} else {
					result := map[string]interface{}{"account": acc, "user": user[0]}
					ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved user with id: %s", id), result, response, out)
				}
			}
		}
	}
}

/** Recipe Handlers **/
func RecipesHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	recipes := make([]Recipe, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("Recipe").GetAll(ctx, &recipes); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve users from datastore", response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, UserSuccessFetch, recipes, response, out)
		}
	} else {
		recipe := make([]Recipe, 0, 1)
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("Recipe").Filter("ID =", num).Limit(1).GetAll(ctx, &recipe); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve recipe with id: %s \nError: %s", id, err.Error()), response, out)
		} else {
			if len(recipe) > 0 {
				if usr, uErr := GetCreatorFromRecipe(&recipe[0], r); uErr != nil {
					ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve recipe with id: %s \nError: %s", id, err.Error()), response, out)
				} else {
					result := map[string]interface{}{"creator": usr, "recipe": recipe[0]}
					ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved recipe with id: %s", id), result, response, out)
				}
			}
		}
	}
}

/** Tag Handlers **/
func TagsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	tags := make([]Tag, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("Tag").GetAll(ctx, &tags); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve tags from datastore", response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, UserSuccessFetch, tags, response, out)
		}
	} else {
		tag := make([]Tag, 0, 1)
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("Tag").Filter("ID =", num).Limit(1).GetAll(ctx, &tag); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve tag with id: %s \nError: %s", id, err.Error()), response, out)
		} else {
			if len(tag) > 0 {
				if usr, uErr := GetCreatorFromTag(&tag[0], r); uErr != nil {
					ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve tag with id: %s \nError: %s", id, err.Error()), response, out)
				} else {
					result := map[string]interface{}{"creator": usr, "tag": tag[0]}
					ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved tag with id: %s", id), result, response, out)
				}
			}
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

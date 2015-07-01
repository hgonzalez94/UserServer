package main

import (
	"github.com/gorilla/mux"
	newappengine "google.golang.org/appengine"
	newdatastore "google.golang.org/appengine/datastore"
	"golang.org/x/net/context"
	"github.com/gorilla/schema"
	"github.com/gorilla/sessions"
	"net/http"
	"fmt"
	"encoding/json"
	"github.com/mrvdot/golang-utils"
	"io"
)

// Global vars
type AuthFunc func(http.ResponseWriter, *http.Request, *Account)
var c context.Context
var decoder *schema.Decoder
var store *sessions.CookieStore
var session *sessions.Session
var vars map[string]string

func init() {
	router := mux.NewRouter()
	decoder = schema.NewDecoder()
	store = sessions.NewCookieStore([]byte("secret"))

	// Initialize Handlers
	router.HandleFunc("/", MainHandler)

	router.HandleFunc("/users", UsersHandler)
	router.HandleFunc("/users/new", NewUserRegistration).
			Methods("POST", "GET").
			Name("CreateAccount")
	router.HandleFunc("/users/authenticate", Authenticate).
			Methods("POST", "GET").
			Name("Authenticate")
	router.HandleFunc("/users/current", VerificationHandler).
			Methods("POST", "GET").
			Name("VerifyEntry")

	router.HandleFunc("/accounts", AccountsHandler)
	router.HandleFunc("/accounts/authenticate", AuthenticateHandler).
	Methods("POST", "GET").
	Name("Authenticate")

	router.HandleFunc("/recipes", RecipesHandler)

	// Hook-up router to go http package
	http.Handle("/", router)
}

func AccountsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	accounts := make([]Account, 0, 10)
	if _, err := newdatastore.NewQuery("Account").GetAll(ctx, &accounts); err != nil {
		response.Code = 403
		response.Message = "Couldn't retrieve accounts from datastore"
	} else {
		response.Code = 420
		response.Message = "dale got all accounts"
		response.Result = accounts
	}
	out.Encode(response)
}

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	apikey:= r.FormValue("apikey")
	slug := r.FormValue("slug")
	if slug != "" && apikey != "" {
		account, err := authenticateAccount(ctx, slug, apikey)
		if err != nil {
			response.Code = 403
			response.Message = "error fetching account"
		} else {
			response.Code = 202
			response.Message = "success fetching user: " + account.Name
			response.Result = account
		}
	} else {
		response.Code = http.StatusBadRequest
		response.Message = "slug must be provided"
	}

	out.Encode(response)
}

func VerificationHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	currentAccount, err := GetAccount(ctx)
	if err != nil {
		response.Code = 403
		response.Message = "error fetching user"
	} else {
		response.Code = 202
		response.Message = "success fetching user: " + currentAccount.Name
		response.Result = currentAccount
		// test slice
//		slices := []Account{currentAccount}
//		response.Result = slices
	}
	out.Encode(response)
}

func Authenticate(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	data := &utils.ApiResponse{}
	_, err := AuthenticateRequest(r, w)
	session, err := GetSession(ctx)
	if err != nil {
//		ctx.Errorf(err.Error())
		data.Code = 403
		data.Message = err.Error()
	} else {
		data.Code = 200
		data.Data = map[string]interface{}{
			"session": session.Key, // Probably not needed anymore, kept for backwards compatibility
		}
	}
	out.Encode(data)
}

func NewAccountFromUser(user *User) (*Account, error) {
	uname := ""
	if user.Username != "" {
		uname = user.Email
	} else if user.Email != "" {
		uname = user.Email
	}
	if uname != "" {
		acct := &Account{
			Name:	uname,
			Active:	true,
		}
		return acct, nil
	}
	return nil, InvalidAcctUsr
}

func NewUserFromFormData(r *http.Request) (*User, error) {
	firstName := r.FormValue("firstName")
	lastName := r.FormValue("lastName")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if firstName != "" && lastName != "" && username != "" && email != "" && password != "" {
		user := &User{
			Username:	username,
			FirstName:	firstName,
			LastName:	lastName,
			Email:		email,
		}
		return user, nil
	}

	return nil, InvalidUserForm
}

func NewUserRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
//	usr, err := NewUserFromFormData(r)
	acct := &Account{}
	name := r.FormValue("account")
	if name != "" {
		acct = &Account{
			Name:   name,
			Active: true,
		}
	} else {
		dec := json.NewDecoder(r.Body)
		defer r.Body.Close()
		err := dec.Decode(acct)
		if err != nil {
			if err == io.EOF {
				response.Code = http.StatusBadRequest
				response.Message = "Account name must be provided"
			} else {
				response.Code = http.StatusInternalServerError
				response.Message = err.Error()
			}
			out.Encode(response)
			return
		}
	}
	_, err := Save(ctx, acct)
	if err != nil {
		response.Code = http.StatusInternalServerError
		response.Message = "Error saving new account: " + err.Error()
		out.Encode(response)
		return
	}
	response.Code = 200
	response.Result = acct
	out.Encode(response)
}

func RecipesHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "recipes")
}

func UsersHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	users := make([]User, 0, 10)
	if _, err := newdatastore.NewQuery("User").GetAll(ctx, &users); err != nil {
		response.Code = 403
		response.Message = "Couldn't retrieve accounts from datastore"
	} else {
		response.Code = 420
		response.Message = "dale got all users"
		response.Result = users
	}
	out.Encode(response)
}

func MainHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "success")
}


// AuthenticatedFunc wraps a function to ensure the request is authenticated
// before passing through to the wrapped function.
// Wrapped function can be either http.HandlerFunc or AuthFunc (receives http.ResponseWriter, *http.Request, *Account)
// BUG - Type switch is panicking way too often right now, need to inspect
func AuthenticatedFunc(fn interface{}) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		acct, err := AuthenticateRequest(req, rw)
		if err != nil {
			if err == Unauthenticated {
				rw.WriteHeader(http.StatusUnauthorized)
			} else {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(err.Error()))
			}
			return
		}
		switch fn := fn.(type) {
			case AuthFunc:
			fn(rw, req, acct)
			case http.HandlerFunc:
			fn(rw, req)
			default:
			panic("Unsupported func passed to AuthenticatedFunc, must be AuthFunc or http.HandlerFunc")
		}
		ClearAuthenticatedRequest(req)
	}
}

// AuthenicatedHandler wraps a handler and ensures everything that passes through it
// is authenticated. Useful when an entire module/subrouter should be gated by authentication
func AuthenticatedHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := AuthenticateRequest(req, rw)
		if err != nil {
			if err == Unauthenticated {
				rw.WriteHeader(http.StatusUnauthorized)
			} else {
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(err.Error()))
			}
			return
		}
		handler.ServeHTTP(rw, req)
		ClearAuthenticatedRequest(req)
	})
}

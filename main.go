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
	"github.com/hgonzalez94/osin"
	"net/url"
//	"reflect"
//	"strconv"
)

// Global vars
type AuthFunc func(http.ResponseWriter, *http.Request, *Account)
var c context.Context
var decoder *schema.Decoder
var store *sessions.CookieStore
var session *sessions.Session
var vars map[string]string

func init() {
	// Routers and main website handling
	router := mux.NewRouter()
	decoder = schema.NewDecoder()
	store = sessions.NewCookieStore([]byte("secret"))

	/** Begin OAuth2 Handling **/
	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{osin.REFRESH_TOKEN}
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = false
	server := osin.NewServer(sconfig, NewStorage())

	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
//			if !example.HandleLoginPage(ar, w, r) {
//				return
//			}
			ar.UserData = struct{ Login string }{Login: "test"}
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		if !resp.IsError {
			resp.Output["custom_parameter"] = 187723
		}
		osin.OutputJSON(resp, w, r)
	})

	// Application home endpoint
	router.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=token&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Implict</a><br/>", url.QueryEscape("http://localhost:8080/appauth/token.json"))))
		w.Write([]byte("</body></html>"))
	})

	// Application destination - CODE
	router.HandleFunc("/appauth/code.json", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		out := json.NewEncoder(w)
		response := &utils.ApiResponse{}

		at := r.Form.Get("access_token")
		tt := r.Form.Get("token_type")
		ei := r.Form.Get("expires_in")
		rt := r.Form.Get("refresh_token")

		result := map[string]interface{}{"access_token": at, "token_type": tt, "expires_in": ei, "refresh_token": rt}
		ServerResponse(ServerExecutionSuccess, "Access Info Success", result, response, out)
		/** End Download Access Token **/
	})

	// Application destination - TOKEN
	router.HandleFunc("/appauth/token.json", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		out := json.NewEncoder(w)
		response := &utils.ApiResponse{}

		at := r.Form.Get("access_token")
		tt := r.Form.Get("token_type")
		ei := r.Form.Get("expires_in")
		rt := r.Form.Get("refresh_token")

		result := map[string]interface{}{"access_token": at, "token_type": tt, "expires_in": ei, "refresh_token": rt}
		ServerResponse(ServerExecutionSuccess, "Access Info Success", result, response, out)
	})
	/** Begin OAuth2 Handling **/

	// Initialize Handlers
	router.HandleFunc("/", RootHandler)

	router.HandleFunc("/users.json", UsersHandler)
	router.HandleFunc("/users/new.json", NewUserRegistration).
	Methods("POST", "GET").
	Name("CreateAccount")
	router.HandleFunc("/users/authenticate.json", Authenticate).
	Methods("POST", "GET").
	Name("Authenticate")
	router.HandleFunc("/users/current.json", VerificationHandler).
	Methods("POST", "GET").
	Name("VerifyEntry")

	router.HandleFunc("/accounts.json", AccountsHandler)
	router.HandleFunc("/accounts/authenticate.json", AuthenticateHandler).
	Methods("POST", "GET").
	Name("Authenticate")

	// Recipes
	router.HandleFunc("/recipes.json", RecipesHandler)
	router.HandleFunc("/recipes/new.json", CreateNewRecipe).
	Methods("POST", "GET").
	Name("CreateRecipe")

	// Tags
	router.HandleFunc("/tags.json", TagsHandler)
	router.HandleFunc("/tags/new.json", CreateNewTag).
	Methods("POST", "GET").
	Name("CreateTag")

	// Hook-up router to go http package
	http.Handle("/", router)
}

/**
	Api Func
 */

func AuthenticateHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	apikey:= r.FormValue("apikey")
	slug := r.FormValue("slug")
	if slug != "" && apikey != "" {
		account, err := authenticateAccount(ctx, slug, apikey)
		if err != nil {
			response.Code = ServerExecutionError
			response.Message = "error fetching account"
		} else {
			response.Code = ServerExecutionSuccess
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
		ServerError(ServerExecutionError, UserErrorFetch, response, out)
	} else {
		ServerResponse(ServerExecutionSuccess, UserSuccessFetch, currentAccount, response, out)
		// test slice
		//		slices := []Account{currentAccount}
		//		response.Result = slices
	}
}

func Authenticate(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	data := &utils.ApiResponse{}
	_, err := AuthenticateRequest(r, w)
	session, err := GetSession(ctx)
	if err != nil {
		ServerError(ServerExecutionError, "error fetching user", data, out)
	} else {
		data.Code = ServerExecutionSuccess
		data.Data = map[string]interface{}{
			"session": session.Key, // Probably not needed anymore, kept for backwards compatibility
		}
	}
	out.Encode(data)
}

func CreateNewTag(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	tag, err := NewTagFromFormData(r)
	if err != nil {
		ServerError(ServerExecutionError, TagFormError, response, out)
	} else {
		_, terr := Save(ctx, tag)
		if terr != nil {
			ServerError(ServerExecutionError, NewTagError + " " + terr.Error(), response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, NewTagSuccess, tag, response, out)
		}
	}
}

func NewRatingFromFormData(r *http.Request) (*Rating, error) {
	return nil, InvalidRatingForm
}

func CreateNewRecipe(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	recipe, err := NewRecipeFromFormData(r)
	if err != nil {
		ServerError(ServerExecutionError, RecipeFormError, response, out)
	} else {
		_, rerr := Save(ctx, recipe)
		if rerr != nil {
			ServerError(ServerExecutionError, NewRecipeError + " " + rerr.Error(), response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, NewRecipeSuccess, recipe, response, out)
		}
	}
}

func NewUserRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	usr, err := NewUserFromFormData(r)
	if UserCredentialsAreUnique(usr.Username, usr.Email, r) {
		if err != nil {
			ServerError(ServerExecutionError, UserErrorSave, response, out)
		} else {
			acct, err := NewAccountFromUser(usr)
			if err != nil {
				ServerError(ServerExecutionError, AccountErrorSave + " " + err.Error(), response, out)
			} else {
				_, uerr := Save(ctx, usr)
				if uerr != nil {
					ServerError(http.StatusInternalServerError, NewUserRegError + " " + uerr.Error(), response, out)
				} else {
					_, aerr := Save(ctx, acct)
					if aerr != nil {
						ServerError(http.StatusInternalServerError, NewUserRegError + " " + aerr.Error(), response, out)
					} else {
						result := map[string]interface{}{"account": acct, "user": usr}
						ServerResponse(UserRegistrationSuccess, NewUserRegSuccess, result, response, out)
					}
				}
			}
		}
	} else {
		ServerError(ServerExecutionError, "Duplicate Username Error", response, out)
	}
}

func RecipesHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	recipes := make([]Recipe, 0, 10)
	if _, err := newdatastore.NewQuery("Recipe").GetAll(ctx, &recipes); err != nil {
		response.Code = ServerExecutionError
		response.Message = "Couldn't retrieve recipes from datastore" + " " + err.Error()
	} else {
		response.Code = ServerExecutionSuccess
		response.Message = "dale got all recipes"
		response.Result = recipes
		//		data := make(map[string]interface{})
		//		for idx := range recipes {
		//			recipe := recipes[idx]
		//			key := strconv.Itoa(idx)
		//			data[key] = recipe
		//		}
		//		response.Data = data
	}
	out.Encode(response)
}

func TagsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	tags := make([]Tag, 0, 10)
	if _, err := newdatastore.NewQuery("Tag").GetAll(ctx, &tags); err != nil {
		response.Code = ServerExecutionError
		response.Message = "Couldn't retrieve tags from datastore" + " " + err.Error()
	} else {
		response.Code = ServerExecutionSuccess
		response.Message = "dale got all tags"
		response.Result = tags
	}
	out.Encode(response)
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

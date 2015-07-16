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
	"github.com/RangelReale/osin"
	"github.com/RangelReale/osin/example"
	"net/url"
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

	// OAuth2 Handling

	cfg := osin.NewServerConfig()
	cfg.AllowGetAccessRequest = true
	cfg.AllowClientSecretInParams = true
	server := osin.NewServer(cfg, NewStorage())

	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if !example.HandleLoginPage(ar, w, r) {
				return
			}
			ar.Authorized = true
			server.FinishAuthorizeRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			ar.Authorized = true
			server.FinishAccessRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR: %s\n", resp.InternalError)
		}
		osin.OutputJSON(resp, w, r)
	})

	router.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}
		osin.OutputJSON(resp, w, r)
	})

	router.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))
		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Login</a><br/>", url.QueryEscape("http://localhost:8080/appauth/code"))))
		w.Write([]byte("</body></html>"))
	})

	router.HandleFunc("/appauth/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		code := r.Form.Get("code")

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - CODE<br/>"))
		defer w.Write([]byte("</body></html>"))

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
			url.QueryEscape("http://localhost:8080/appauth/code"), url.QueryEscape(code))

		// if parse, download and parse json
		if r.Form.Get("doparse") == "1" {
			err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
				&osin.BasicAuth{"1234", "aabbccdd"}, jr)
			if err != nil {
				w.Write([]byte(err.Error()))
				w.Write([]byte("<br/>"))
			}
		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
		}

		// show json access token
		if at, ok := jr["access_token"]; ok {
			w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
		}

		w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

		// output links
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

		cururl := *r.URL
		curq := cururl.Query()
		curq.Add("doparse", "1")
		cururl.RawQuery = curq.Encode()
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))
	})

	// Initialize Handlers
	router.HandleFunc("/", MainHandler)

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
		ServerError(403, UserErrorFetch, response, out)
	} else {
		ServerResponse(202, UserSuccessFetch, currentAccount, response, out)
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
		ServerError(403, "error fetching user", data, out)
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

func NewRecipeFromFormData(r *http.Request) (*Recipe, error) {
	name := r.FormValue("name")
	imgUrl := r.FormValue("imgUrl")

	if name != "" && imgUrl != "" {
		recipe := &Recipe{
			Name:	name,
			ImgUrl: imgUrl,
		}
		return recipe, nil
	}
	return nil, InvalidRecipeForm
}

func NewTagFromFormData(r *http.Request) (*Tag, error) {
	name := r.FormValue("name")

	if name != "" {
		tag := &Tag{
			Name:	name,
		}
		return tag, nil
	}
	return nil, InvalidTagForm
}

func CreateNewTag(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	tag, err := NewTagFromFormData(r)
	if err != nil {
		ServerError(403, TagFormError, response, out)
	} else {
		_, terr := Save(ctx, tag)
		if terr != nil {
			ServerError(403, NewTagError + " " + terr.Error(), response, out)
		} else {
			ServerResponse(202, NewTagSuccess, tag, response, out)
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
		ServerError(403, RecipeFormError, response, out)
	} else {
		_, rerr := Save(ctx, recipe)
		if rerr != nil {
			ServerError(403, NewRecipeError + " " + rerr.Error(), response, out)
		} else {
			ServerResponse(202, NewRecipeSuccess, recipe, response, out)
		}
	}
}

func NewUserRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := newappengine.NewContext(r)
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	usr, err := NewUserFromFormData(r)
	if err != nil {
		ServerError(403, UserErrorSave, response, out)
	} else {
		acct, err := NewAccountFromUser(usr)
		if err != nil {
			ServerError(403, AccountErrorSave + " " + err.Error(), response, out)
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
					ServerResponse(200, NewUserRegSuccess, result, response, out)
				}
			}
		}
	}
//	acct := &Account{}
//	name := r.FormValue("account")
//	if name != "" {
//		acct = &Account{
//			Name:   name,
//			Active: true,
//		}
//	} else {
//		dec := json.NewDecoder(r.Body)
//		defer r.Body.Close()
//		err := dec.Decode(acct)
//		if err != nil {
//			if err == io.EOF {
//				response.Code = http.StatusBadRequest
//				response.Message = "Account name must be provided"
//			} else {
//				response.Code = http.StatusInternalServerError
//				response.Message = err.Error()
//			}
//			out.Encode(response)
//			return
//		}
//	}
//	_, aerr := Save(ctx, acct)
//	if aerr != nil {
//		ServerError(http.StatusInternalServerError, AccountErrorSave, response, out)
//		return
//	}
//	response.Code = 200
//	response.Result = acct
//	out.Encode(response)
}

func RecipesHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	recipes := make([]Recipe, 0, 10)
	if _, err := newdatastore.NewQuery("Recipe").GetAll(ctx, &recipes); err != nil {
		response.Code = 403
		response.Message = "Couldn't retrieve recipes from datastore" + " " + err.Error()
	} else {
		response.Code = 420
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
		response.Code = 403
		response.Message = "Couldn't retrieve tags from datastore" + " " + err.Error()
	} else {
		response.Code = 420
		response.Message = "dale got all tags"
		response.Result = tags
	}
	out.Encode(response)
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
	fmt.Fprintf(w, "ready recipe")
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

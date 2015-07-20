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

	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN, osin.PASSWORD, osin.CLIENT_CREDENTIALS, osin.ASSERTION}
	sconfig.AllowGetAccessRequest = true
	server := osin.NewServer(sconfig, NewStorage())

	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAuthorizeRequest(resp, r); ar != nil {
			if !example.HandleLoginPage(ar, w, r) {
				return
			}
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

	// Access token endpoint
	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ar := server.HandleAccessRequest(resp, r); ar != nil {
			switch ar.Type {
			case osin.AUTHORIZATION_CODE:
				ar.Authorized = true
			case osin.REFRESH_TOKEN:
				ar.Authorized = true
			case osin.PASSWORD:
				if ar.Username == "test" && ar.Password == "test" {
					ar.Authorized = true
				}
			case osin.CLIENT_CREDENTIALS:
				ar.Authorized = true
			case osin.ASSERTION:
				if ar.AssertionType == "urn:osin.example.complete" && ar.Assertion == "osin.data" {
					ar.Authorized = true
				}
			}
			server.FinishAccessRequest(resp, r, ar)
		}
		if resp.IsError && resp.InternalError != nil {
			fmt.Printf("ERROR__: %s\n", resp.InternalError)
		}
		if !resp.IsError {
			resp.Output["custom_parameter"] = 19923
		}
		osin.OutputJSON(resp, w, r)
	})

	// Information endpoint
	router.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		resp := server.NewResponse()
		defer resp.Close()

		if ir := server.HandleInfoRequest(resp, r); ir != nil {
			server.FinishInfoRequest(resp, r, ir)
		}
		osin.OutputJSON(resp, w, r)
	})

	// Application home endpoint
	router.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>"))

		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Code</a><br/>", url.QueryEscape("http://localhost:8080/appauth/code"))))
		w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=token&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Implict</a><br/>", url.QueryEscape("http://localhost:8080/appauth/token"))))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/password\">Password</a><br/>")))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/client_credentials\">Client Credentials</a><br/>")))
		w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/assertion\">Assertion</a><br/>")))

		w.Write([]byte("</body></html>"))
	})

	// Application destination - CODE
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
		aurl := fmt.Sprintf("/token?grant_type=authorization_code&client_id=1234&state=xyz&redirect_uri=%s&code=%s",
			url.QueryEscape("http://localhost:8080/appauth/code"), url.QueryEscape(code))

		// if parse, download and parse json
//		if r.Form.Get("doparse") == "1" {
			err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
				&osin.BasicAuth{"1234", "aabbccdd"}, jr, r)
			if err != nil {
				w.Write([]byte(err.Error()))
				w.Write([]byte("<br/>"))
			}
//		}

		// show json error
		if erd, ok := jr["error"]; ok {
			w.Write([]byte(fmt.Sprintf("ERROR__2: %s<br/>\n", erd)))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}
	})

	// Application destination - TOKEN
	router.HandleFunc("/appauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - TOKEN<br/>"))

		w.Write([]byte("Response data in fragment - not acessible via server - Nothing to do"))

		w.Write([]byte("</body></html>"))
	})

	// Application destination - PASSWORD
	router.HandleFunc("/appauth/password", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - PASSWORD<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=password&scope=everything&username=%s&password=%s",
			"test", "test")

		// download token
		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - CLIENT_CREDENTIALS
	router.HandleFunc("/appauth/client_credentials", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - CLIENT CREDENTIALS<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=client_credentials")

		// download token
		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - ASSERTION
	router.HandleFunc("/appauth/assertion", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - ASSERTION<br/>"))

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=assertion&assertion_type=urn:osin.example.complete&assertion=osin.data")

		// download token
		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}

		w.Write([]byte("</body></html>"))
	})

	// Application destination - REFRESH
	router.HandleFunc("/appauth/refresh", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - REFRESH<br/>"))
		defer w.Write([]byte("</body></html>"))

		code := r.Form.Get("code")

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=refresh_token&refresh_token=%s", url.QueryEscape(code))

		// download token
		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}

		if at, ok := jr["access_token"]; ok {
			rurl := fmt.Sprintf("/appauth/info?code=%s", at)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
		}
	})

	// Application destination - INFO
	router.HandleFunc("/appauth/info", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		w.Write([]byte("<html><body>"))
		w.Write([]byte("APP AUTH - INFO<br/>"))
		defer w.Write([]byte("</body></html>"))

		code := r.Form.Get("code")

		if code == "" {
			w.Write([]byte("Nothing to do"))
			return
		}

		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/info?code=%s", url.QueryEscape(code))

		// download token
		err := example.DownloadAccessToken(fmt.Sprintf("http://localhost:8080%s", aurl),
			&osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr, r)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
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

		if rt, ok := jr["refresh_token"]; ok {
			rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
			w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
		}
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

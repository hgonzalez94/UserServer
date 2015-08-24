// Package aeutils provides some useful utilities for working with
// structs and other objects within the Google App Engine architecture.
package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/mrvdot/golang-utils"
	"github.com/qedus/nds"

	"golang.org/x/net/context"

	newappengine "google.golang.org/appengine"
	newdatastore "google.golang.org/appengine/datastore"

	"encoding/json"
	"log"
	"net/http"
	"strconv"
)

const (
	AccountErrorFetch   = "Error fetching account"
	AccountErrorSave    = "Error saving new account"
	AccountSuccessFetch = "successfully fetched current account"

	UserErrorFetch   = "Error fetching user"
	UserErrorSave    = "Error saving new user"
	UserSuccessFetch = "successfully fetched user"

	NewUserRegSuccess = "successfully registered user"
	NewUserRegError   = "error registering user"

	NewRecipeSuccess = "successfully created new recipe"
	NewRecipeError   = "error creating new recipe"
	RecipeFormError  = "error creating recipe from form data"

	NewTagSuccess   = "successfully created new tag"
	NewTagError     = "error creating new tag"
	TagFormError    = "error creating tag from form data"
	TagSuccessFetch = "successfully fetched tags"

	NewRatingSuccess   = "successfully created new rating"
	NewRatingError     = "error creating new rating"
	RatingFormError    = "error creating rating from form data"
	RatingSuccessFetch = "successfully fetched ratings"
)

var (
	// Set to true to use NDS package for Put/Get methods
	UseNDS = false
)

// GenerateUniqueSlug generates a slug that's unique within the newdatastore for this type
// Uses utils.GenerateSlug for initial slug, and appends "-N" where N is an auto-incrementing number
// Until it finds a slug that doesn't already exist for this kind
func GenerateUniqueSlug(ctx context.Context, kind string, s string) (slug string) {
	slug = utils.GenerateSlug(s)
	others, err := newdatastore.NewQuery(kind).
		Filter("Slug = ", slug).
		Count(ctx)
	if err != nil {
		//		ctx.Errorf("[aeutils/GenerateUniqueSlug] %v", err.Error())
		return ""
	}
	if others == 0 {
		return slug
	}
	counter := 2
	baseSlug := slug
	for others > 0 {
		slug = fmt.Sprintf("%v-%d", baseSlug, counter)
		others, err = newdatastore.NewQuery(kind).
			Filter("Slug = ", slug).
			Count(ctx)
		if err != nil {
			//			ctx.Errorf("[aeutils/GenerateUniqueSlug] %v", err.Error())
			return ""
		}
		counter = counter + 1
	}
	return slug
}

// PreSave checks for
// * Method 'BeforeSave' that receives appengine.Context as it's first parameter
//   This can be used for any on save actions that need to be performed (generate a slug, store LastUpdated, or create Key field (see below))
func PreSave(ctx context.Context, obj interface{}) error {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind() == reflect.Ptr {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind() != reflect.Struct {
		return errors.New(fmt.Sprintf("Must pass a valid object (struct) to aeutils.Save: passed %v", str.Kind()))
	}
	preSave(ctx, val)
	return nil
}

// internal presave method that uses values, so we don't have to check twice
func preSave(ctx context.Context, val reflect.Value) {
	if bsMethod := val.MethodByName("BeforeSave"); bsMethod.IsValid() {
		bsMethod.Call([]reflect.Value{reflect.ValueOf(ctx)})
	}
}

// Save takes an context.Context and an struct (or pointer to struct) to save in the newdatastore
// Uses reflection to validate obj is able to be saved. Additionally checks for:
//
// * Field 'Key' of kind *newdatastore.Key. If exists and has a valid key, uses that for storing in newdatastore
// 	 ** Important. Due to newdatastore limitations, this field must not actually be stored in the newdatastore (ie, needs struct tag `newdatastore:"-")
// * Field 'ID' of kind int64 to be used as the numeric ID for a newdatastore key
//	 If key was not retrieved from Key field, ID field is used to create a new key based on that ID
//	 If struct has ID field but no value for it, Save allocates an ID from the newdatastore and sets it in that field before saving
// * Method 'AfterSave' that receives appengineappengine.Context and *newdatastore.Key as it's parameters
//   Useful for any post save processing that you might want to do
//
// Finally, ID and Key fields (if they exist) are set with any generated values from Saving obj
func Save2(ctx context.Context, obj interface{}) (key *newdatastore.Key, err error) {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind() == reflect.Ptr {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind() != reflect.Struct {
		return nil, errors.New(fmt.Sprintf("Must pass a valid object (struct) to aeutils.Save: passed %v", str.Kind()))
	}
	preSave(ctx, val)
	//check for key field first
	keyField := str.FieldByName("Key")
	if keyField.IsValid() {
		keyInterface := keyField.Interface()
		key, _ = keyInterface.(*newdatastore.Key)
	}
	idField := str.FieldByName("ID")
	dsKind := getDatastoreKind(kind)
	if key == nil {
		if idField.IsValid() && isInt(idField.Kind()) && idField.Int() != 0 {
			key = newdatastore.NewKey(ctx, dsKind, "", idField.Int(), nil)
		} else {
			newId, _, err := newdatastore.AllocateIDs(ctx, dsKind, nil, 1)
			if err == nil {
				if idField.IsValid() && isInt(idField.Kind()) {
					idField.SetInt(newId)
				}
				key = newdatastore.NewKey(ctx, dsKind, "", newId, nil)
			} else {
				key = newdatastore.NewIncompleteKey(ctx, dsKind, nil)
			}
		}
	}
	if UseNDS {
		//		key, err = nds.Put(ctx, key, obj)
	} else {
		//		key, err = newdatastore.Put(ctx, key, obj)
		//		log.Println("savin: " + key)
	}
	if err != nil {
		//		ctx.Errorf("[aeutils/Save]: %v", err.Error())
	} else {
		if keyField.IsValid() {
			keyField.Set(reflect.ValueOf(key))
		}
		if idField.IsValid() && isInt(idField.Kind()) {
			idField.SetInt(key.IntID())
		}
		if asMethod := val.MethodByName("AfterSave"); asMethod.IsValid() {
			asMethod.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(key)})
		}
	}
	return
}

func Save(ctx context.Context, obj interface{}) (key *newdatastore.Key, err error) {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind() == reflect.Ptr {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind() != reflect.Struct {
		return nil, errors.New(fmt.Sprintf("Must pass a valid object (struct) to aeutils.Save: passed %v", str.Kind()))
	}
	preSave(ctx, val)
	//check for key field first
	keyField := str.FieldByName("Key")
	if keyField.IsValid() {
		keyInterface := keyField.Interface()
		key, _ = keyInterface.(*newdatastore.Key)
	}
	idField := str.FieldByName("ID")
	dsKind := getDatastoreKind(kind)
	if key == nil {
		if idField.IsValid() && isInt(idField.Kind()) && idField.Int() != 0 {
			key = newdatastore.NewKey(ctx, dsKind, "", idField.Int(), nil)
		} else {
			newId, _, err := newdatastore.AllocateIDs(ctx, dsKind, nil, 1)
			if err == nil {
				if idField.IsValid() && isInt(idField.Kind()) {
					idField.SetInt(newId)
				}
				key = newdatastore.NewKey(ctx, dsKind, "", newId, nil)
			} else {
				key = newdatastore.NewIncompleteKey(ctx, dsKind, nil)
			}
		}
	}
	if UseNDS {
		key, err = nds.Put(ctx, key, obj)
	} else {
		key, err = newdatastore.Put(ctx, key, obj)
	}
	if err != nil {
		//		ctx.Errorf("[aeutils/Save]: %v", err.Error())
	} else {
		if keyField.IsValid() {
			keyField.Set(reflect.ValueOf(key))
		}
		if idField.IsValid() && isInt(idField.Kind()) {
			idField.SetInt(key.IntID())
		}
		if asMethod := val.MethodByName("AfterSave"); asMethod.IsValid() {
			asMethod.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(key)})
		}
	}
	return
}

func isInt(kind reflect.Kind) bool {
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

// ExistsInDatastore takes an appengine Context and an interface checks if that interface already exists in newdatastore
// Will call any 'BeforeSave' method as appropriate, in case that method sets up a 'Key' field, otherwise checks for an ID field
// and assumes that's the newdatastore IntID
func ExistsInDatastore(ctx context.Context, obj interface{}) bool {
	kind, val := reflect.TypeOf(obj), reflect.ValueOf(obj)
	str := val
	if val.Kind().String() == "ptr" {
		kind, str = kind.Elem(), val.Elem()
	}
	if str.Kind().String() != "struct" {
		return false
	}
	dsKind := getDatastoreKind(kind)
	if bsMethod := val.MethodByName("BeforeSave"); bsMethod.IsValid() {
		bsMethod.Call([]reflect.Value{reflect.ValueOf(ctx)})
	}
	var key *newdatastore.Key
	//check for key field first
	keyField := str.FieldByName("Key")
	if keyField.IsValid() {
		keyInterface := keyField.Interface()
		key, _ = keyInterface.(*newdatastore.Key)
	}
	idField := str.FieldByName("ID")
	if key == nil {
		if idField.IsValid() && idField.Int() != 0 {
			key = newdatastore.NewKey(ctx, dsKind, "", idField.Int(), nil)
		}
	}
	if key == nil {
		return false
	}
	var err error
	if UseNDS {
		err = nds.Get(ctx, key, obj)
	} else {
		err = newdatastore.Get(ctx, key, obj)
	}
	if err != nil {
		return false
	}
	return true
}

// getDatastoreKind takes a reflect kind and returns a valid string value matching that kind
// Strips off any package namespacing, so 'accounts.Account' becomes just 'Account'
func getDatastoreKind(kind reflect.Type) (dsKind string) {
	dsKind = kind.String()
	if li := strings.LastIndex(dsKind, "."); li >= 0 {
		//Format kind to be in a standard format used for newdatastore
		dsKind = dsKind[li+1:]
	}
	return
}

/** Server Responses **/
func ServerResponse(code int, msg string, result interface{}, data *utils.ApiResponse, out *json.Encoder) {
	data.Code = code
	data.Message = msg
	data.Result = result
	out.Encode(data)
}

func ServerError(code int, msg string, data *utils.ApiResponse, out *json.Encoder) {
	data.Code = code
	data.Message = msg
	out.Encode(data)
}

/** Server Utility Methods **/
func UserCredentialsAreUnique(username string, email string, r *http.Request) bool {
	ctx := newappengine.NewContext(r)
	user := make([]User, 0, 1)
	if email != "" {
		if _, err := newdatastore.NewQuery("User").Filter("Email =", email).Limit(1).GetAll(ctx, &user); err != nil {
			return false
		}
	}
	if username != "" {
		if _, err := newdatastore.NewQuery("User").Filter("Username =", username).Limit(1).GetAll(ctx, &user); err != nil {
			return false
		}
	}
	if len(user) < 1 {
		return true
	}
	return false
}

func GetAccountFromUser(user *User, r *http.Request) (*Account, error) {
	ctx := newappengine.NewContext(r)
	acc := make([]Account, 0, 1)
	if user != nil {
		if _, err := newdatastore.NewQuery("Account").Filter("Name =", user.AccountName).Limit(1).GetAll(ctx, &acc); err != nil {
			return nil, err
		} else {
			return &acc[0], nil
		}
	}
	return nil, nil
}

func GetCreatorFromRecipe(recipe *Recipe, r *http.Request) (*User, error) {
	ctx := newappengine.NewContext(r)
	usr := make([]User, 0, 1)
	if recipe != nil {
		if _, err := newdatastore.NewQuery("User").Filter("ID =", recipe.CreatorID).Limit(1).GetAll(ctx, &usr); err != nil {
			return nil, err
		} else {
			return &usr[0], nil
		}
	}
	return nil, nil
}

func GetCreatorFromTag(tag *Tag, r *http.Request) (*User, error) {
	ctx := newappengine.NewContext(r)
	usr := make([]User, 0, 1)
	if tag != nil {
		if _, err := newdatastore.NewQuery("User").Filter("ID =", tag.CreatorID).Limit(1).GetAll(ctx, &usr); err != nil {
			return nil, err
		} else {
			return &usr[0], nil
		}
	}
	return nil, nil
}

func GetCreatorFromRating(rating *Rating, r *http.Request) (*User, error) {
	ctx := newappengine.NewContext(r)
	usr := make([]User, 0, 1)
	if rating != nil {
		if _, err := newdatastore.NewQuery("User").Filter("ID =", rating.CreatorID).Limit(1).GetAll(ctx, &usr); err != nil {
			return nil, err
		} else {
			return &usr[0], nil
		}
	}
	return nil, nil
}

func GetRecipeFromRating(rating *Rating, r *http.Request) (*Recipe, error) {
	ctx := newappengine.NewContext(r)
	rting := make([]Recipe, 0, 1)
	if rting != nil {
		if _, err := newdatastore.NewQuery("Recipe").Filter("ID =", rating.RecipeID).Limit(1).GetAll(ctx, &rting); err != nil {
			return nil, err
		} else {
			return &rting[0], nil
		}
	}
	return nil, nil
}

/** Model Utility Methods **/
func NewUserFromFormData(r *http.Request) (*User, error) {
	firstName := r.FormValue("firstName")
	lastName := r.FormValue("lastName")
	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	if firstName != "" && lastName != "" && username != "" && email != "" && password != "" {
		user := &User{
			Username:  username,
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
		}
		return user, nil
	}

	return nil, InvalidUserForm
}

func NewUserFromFormBody(r *http.Request) (*User, error) {
	var tc map[string]interface{}

	decoder := json.NewDecoder(r.Body)

	err := decoder.Decode(&tc)
	var firstName = tc["firstName"].(string)
	var lastName = tc["lastName"].(string)
	var username = tc["username"].(string)
	var email = tc["email"].(string)
	var password = tc["password"].(string)

	if firstName != "" && lastName != "" && username != "" && email != "" && password != "" && err == nil {
		user := &User{
			Username:  username,
			FirstName: firstName,
			LastName:  lastName,
			Email:     email,
		}
		return user, nil
	}

	return nil, InvalidUserForm
}

type test_struct struct {
	Name      string
	ImgURL    string
	CreatorID string
}

type test_collection struct {
	Group map[string]test_struct
}

func NewRecipeCollectionFromFormBody(r *http.Request) (*map[string]interface{}, error) {
	//	tc := new(test_collection)
	var tc map[string]interface{}
	//	var data = &tc.Group

	decoder := json.NewDecoder(r.Body)
	//	err := decoder.Decode(data)
	err := decoder.Decode(&tc)
	var testCollection = tc["test_collection"].(map[string]interface{})
	var name = testCollection["name"].(string)
	log.Println("FOUND ME " + name)
	if err != nil {
		return nil, InvalidRecipeForm
	}

	return &tc, nil
}

func NewRecipeFromFormBody(r *http.Request) (*Recipe, error) {
	var tc map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&tc)

	var name = tc["name"].(string)
	var imgUrl = tc["imgUrl"].(string)
	var creatorID = tc["creatorID"].(string) //number
	creatorIDNum, numErr := strconv.ParseInt(creatorID, 10, 64)

	if name != "" && imgUrl != "" && creatorID != "" && err == nil && numErr == nil {
		recipe := &Recipe{
			Name:      name,
			ImgUrl:    imgUrl,
			CreatorID: creatorIDNum,
		}
		return recipe, nil
	}
	return nil, InvalidRecipeForm
}

func NewRecipeFromFormData(r *http.Request) (*Recipe, error) {
	name := r.FormValue("name")
	imgUrl := r.FormValue("imgUrl")
	creatorID := r.FormValue("creatorID")
	creatorIDNum, numErr := strconv.ParseInt(creatorID, 10, 64)

	if name != "" && imgUrl != "" && numErr == nil {
		recipe := &Recipe{
			Name:      name,
			ImgUrl:    imgUrl,
			CreatorID: creatorIDNum,
		}
		return recipe, nil
	}
	return nil, InvalidRecipeForm
	//	return nil, errors.New("invalid form data: " + name + "\n" + imgUrl + "\n" + creatorID + numErr.Error())
}

func NewTagFromFormBody(r *http.Request) (*Tag, error) {
	var tc map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&tc)

	var name = tc["name"].(string)
	//	var creatorID = tc["creatorID"].(int64)
	var creatorID = tc["creatorID"].(string)
	creatorIDNum, numErr := strconv.ParseInt(creatorID, 10, 64)

	if name != "" && creatorID != "" && err == nil && numErr == nil {
		tag := &Tag{
			Name:      name,
			CreatorID: creatorIDNum,
		}
		return tag, nil
	}
	return nil, InvalidTagForm
}

func NewTagFromFormData(r *http.Request) (*Tag, error) {
	name := r.FormValue("name")
	creatorID := r.FormValue("creatorID")
	creatorIDNum, numErr := strconv.ParseInt(creatorID, 10, 64)

	if name != "" && numErr == nil {
		tag := &Tag{
			Name:      name,
			CreatorID: creatorIDNum,
		}
		return tag, nil
	}
	return nil, InvalidTagForm
}

func NewRatingFromFormBody(r *http.Request) (*Rating, error) {
	var tc map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&tc)

	var rating = tc["rating"].(string)
	ratingNum, numErr := strconv.Atoi(rating) // convert to int
	var creatorID = tc["creatorID"].(string)
	creatorIDNum, numErr2 := strconv.ParseInt(creatorID, 10, 64) // convert to int64
	var recipeID = tc["recipeID"].(string)
	recipeIDNum, numErr3 := strconv.ParseInt(recipeID, 10, 64)

	if err == nil && numErr == nil && numErr2 == nil && numErr3 == nil {
		rate := &Rating{
			Rating:    ratingNum,
			CreatorID: creatorIDNum,
			RecipeID:  recipeIDNum,
		}
		return rate, nil
	}
	return nil, InvalidRatingForm
}

func NewRatingFromFormData(r *http.Request) (*Rating, error) {
	rating := r.FormValue("rating")
	creatorID := r.FormValue("creatorID")
	recipeID := r.FormValue("recipeID")
	creatorIDNum, numErr := strconv.ParseInt(creatorID, 10, 64)
	recipeIDNum, numErr2 := strconv.ParseInt(recipeID, 10, 64)
	ratingNum, numErr3 := strconv.Atoi(rating)

	if numErr == nil && numErr2 == nil && numErr3 == nil {
		rate := &Rating{
			Rating:    ratingNum,
			CreatorID: creatorIDNum,
			RecipeID:  recipeIDNum,
		}
		return rate, nil
	}
	return nil, InvalidRatingForm
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
			Name:   uname,
			Active: true,
		}
		return acct, nil
	}
	return nil, InvalidAcctUsr
}

package main

import (
	"encoding/json"
	"fmt"
	"github.com/agnivade/easy-scrypt"
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
	passphrase := "testPass"
	key, err := scrypt.DerivePassphrase(passphrase, 32)
	if err != nil {
		fmt.Fprintf(w, "fucked up deriving passphrase bro")
	}

	fmt.Fprintf(w, "key returned - %v\n", key)
	var result bool

	result, err = scrypt.VerifyPassphrase(passphrase, key)
	if err != nil {
		fmt.Fprintf(w, "couldnt verify password")
	}
	if !result {
		fmt.Fprintf(w, "couldnt verify password pt2: the mixtape")
	} else {
		fmt.Fprintf(w, "passphrase successfully verified")
	}
}

/** User Handlers **/
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)

	var tc map[string]interface{}
	decoder := json.NewDecoder(r.Body)

	errd := decoder.Decode(&tc)
	var email = tc["email"].(string)
	var password = tc["password"].(string)
	if errd == nil && email != "" && password != "" {
		user := make([]User, 0, 1)
		if _, err := newdatastore.NewQuery("User").Filter("Email =", email).Limit(1).GetAll(ctx, &user); err != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve user with email: %v", email), response, out)
		} else {
			if len(user) > 0 { //fetched the nigge
				var result bool
				result, err = scrypt.VerifyPassphrase(password, user[0].EncryptedPassword)
				if err != nil {
					ServerError(ServerExecutionError, "couldnt authenticate user error 1", response, out)
				}
				if !result {
					ServerError(ServerExecutionError, "couldnt authenticate user error 2", response, out)
				} else {
					res := map[string]interface{}{"user": user[0]}
					ServerResponse(ServerExecutionSuccess, fmt.Sprintf("successful login"), res, response, out)
				}
			} else { //suck a dick
				ServerError(ServerExecutionError, "couldnt authenticate user error 3", response, out)
			}
		}
	} else {
		ServerError(ServerExecutionError, "wrong shit submitted holmes", response, out)
	}
}
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

/** API Global Handlers **/
// TODO: add token validation
func GetUserContent(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	userID := r.FormValue("userID")
	if userID == "" {
		ServerError(ServerExecutionError, "missing userID", response, out)
	} else {
		// Fetch Tags
		tags := []Tag{}
		userIDNum, numErr := strconv.ParseInt(userID, 10, 64)
		if _, err := newdatastore.NewQuery("Tag").Filter("CreatorID =", userIDNum).GetAll(ctx, &tags); err != nil || numErr != nil {
			ServerError(ServerExecutionError, "unable to fetch tags", response, out)
		} else {
			// Fetch Recipes
			recipes := []Recipe{}
			if _, err2 := newdatastore.NewQuery("Recipe").Filter("CreatorID =", userIDNum).GetAll(ctx, &recipes); err2 != nil {
				ServerError(ServerExecutionError, "unable to fetch recipes", response, out)
			} else {
				result := map[string]interface{}{"tags": tags, "recipes": recipes}
				ServerResponse(ServerExecutionSuccess, "got user content", result, response, out)
			}
		}
	}
}

func SetRecipeTags(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	//	ctx := newappengine.NewContext(r)

	var tc map[string]interface{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&tc)

	var tagIDs = tc["tagIDs"].([]int64)
	if err != nil {
		ServerError(ServerExecutionError, "failed to decode objects with error: "+err.Error(), response, out)
	} else {
		savedIDs := []int64{}
		tagIdx := 0
		for tagIdx < len(tagIDs) {
			tagID := tagIDs[tagIdx]

			savedIDs = append(savedIDs, tagID)
			tagIdx++
		}
	}
	/*	payload := map[string]interface{}{}
		err := decoder.Decode(&payload)
		if err != nil {
			ServerError(ServerExecutionError, "failed to decode objects with error: "+err.Error(), response, out)
		} else {
			userID := payload["userID"]
			recipeID := payload["recipeID"]
			tagIDs := payload["tagIDS"]
			recipes := []Recipe{}
			if _, err := newdatastore.NewQuery("Recipe").Filter("CreatorID =", userID).Filter("ID =", recipeID).Limit(1).GetAll(ctx, &recipes); err != nil {
				ServerError(ServerExecutionError, "unable to retrieve recipes", response, out)
			} else {
				recipe := &recipes[0]
				recipe.TagIDs = tagIDs.([]int64)
				if _, updateErr := newdatastore.Put(ctx, recipe.Key, recipe); updateErr != nil {
					ServerError(ServerExecutionError, "unable to update entity", response, out)
				} else {
					ServerResponse(ServerExecutionSuccess, "successfully updated entity", recipe, response, out)
				}
			}

		}
	*/
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
			ServerResponse(ServerExecutionSuccess, "Got Recipes Successfully", recipes, response, out)
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
// TODO: Validate uniqueness...in save method
func GenerateTags(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	tagNames := []string{"Dinner", "Lunch", "Breakfast", "Vegetarian", "Treat", "Desert"}
	savedTags := []Tag{}
	tagIdx := 0
	for tagIdx < len(tagNames) {
		tag := &Tag{
			Name:      tagNames[tagIdx],
			CreatorID: 1,
		}
		_, terr := Save(ctx, tag)
		if terr != nil {
			ServerError(ServerExecutionError, NewTagError+"couldn't create tags "+terr.Error(), response, out)
			break
		} else {
			savedTags = append(savedTags, *tag)
			tagIdx++
		}
	}
	ServerResponse(ServerExecutionSuccess, NewTagSuccess, savedTags, response, out)
}

func TagsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	tags := make([]Tag, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("Tag").GetAll(ctx, &tags); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve tags from datastore: "+err.Error(), response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, TagSuccessFetch, tags, response, out)
		}
	} else {
		tag := []Tag{}
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("Tag").Filter("CreatorID =", num).GetAll(ctx, &tag); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve tag with id: %s \nError: %s", id, err.Error()), response, out)
		} else {
			if len(tag) > 0 {
				result := map[string]interface{}{"tag": tag}
				ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved tag with id: %s", id), result, response, out)
			}
		}
	}
}

/** Rating Handlers **/
func RatingsHandler(w http.ResponseWriter, r *http.Request) {
	out := json.NewEncoder(w)
	response := &utils.ApiResponse{}
	ctx := newappengine.NewContext(r)
	ratings := make([]Rating, 0, 10)
	id := r.FormValue("id")
	if id == "" {
		if _, err := newdatastore.NewQuery("Rating").GetAll(ctx, &ratings); err != nil {
			ServerError(ServerExecutionError, "couldnt retrieve ratings from datastore", response, out)
		} else {
			ServerResponse(ServerExecutionSuccess, RatingSuccessFetch, ratings, response, out)
		}
	} else {
		rating := make([]Rating, 0, 1)
		num, numErr := strconv.Atoi(id)
		if _, err := newdatastore.NewQuery("Rating").Filter("ID =", num).Limit(1).GetAll(ctx, &rating); err != nil || numErr != nil {
			ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve rating with id: %s \nError: %s", id, err.Error()), response, out)
		} else {
			if len(rating) > 0 {
				if usr, uErr := GetCreatorFromRating(&rating[0], r); uErr != nil {
					ServerError(ServerExecutionError, fmt.Sprintf("couldnt retrieve rating with id: %s \nError: %s", id, err.Error()), response, out)
				} else {
					result := map[string]interface{}{"creator": usr, "rating": rating[0]}
					ServerResponse(ServerExecutionSuccess, fmt.Sprintf("retrieved rating with id: %s", id), result, response, out)
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

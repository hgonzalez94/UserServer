package main

import (
	"errors"
)

var (
	/** Error Codes **/
	ServerExecutionError    = 403
	ServerExecutionSuccess  = 420
	UserRegistrationSuccess = 200

	/** Server Access Errors **/
	Unauthenticated = errors.New("No account has been authenticated for this request")
	NoSuchSession   = errors.New("No account matches that session")
	NoSuchAccount   = errors.New("No account matches that slug")
	InvalidApiKey   = errors.New("API Key does not match account")
	SessionExpired  = errors.New("Session has expired, please reauthenticate")
	InvalidPassword = errors.New("That password is not valid for this user")

	/** Model Utility Errors (TODO: have one error message for entity creation)**/
	InvalidUserForm   = errors.New("Unable to create a user from supplied form data")
	InvalidAcctUsr    = errors.New("Unable to create an account from supplied user")
	InvalidRecipeForm = errors.New("Unable to create a recipe from supplied form data")
	InvalidTagForm    = errors.New("Unable to create a tag from supplied form data")
	InvalidRatingForm = errors.New("Unable to create a rating from supplied form data")

	/** Model Flow Errors **/
	DuplicateUser = errors.New("An account with those credentials already exists")
)

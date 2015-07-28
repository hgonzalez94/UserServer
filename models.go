package main

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"math/rand"
	"time"

	"code.google.com/p/go-uuid/uuid"

	"errors"
	"github.com/hgonzalez94/osin"
	"golang.org/x/net/context"
	newdatastore "google.golang.org/appengine/datastore"
)

var (
	authenticatedAccounts = map[string]*Account{}
	authenticatedSessions = map[string]*Session{}
	authenticatedUsers    = map[string]*User{}
	sessionToAccount      = map[*Session]*Account{}
	sessionToUser         = map[*Session]*User{}
	sessionsMap           = map[string]*Session{}
	// Headers is a string map to header names used for checking account info in request headers
	Headers = map[string]string{
		"account":  "X-account",  // Account slug
		"key":      "X-key",      // Account key
		"session":  "X-session",  // Session key
		"username": "X-username", // Username (for auth by user instead of account)
		"password": "X-password", // Password (for auth by user)
	}
	// SessionTTL is a time.Duration for how long a session should remain valid since LastUsed
	SessionTTL = time.Duration(3 * time.Hour)
)

/** oAuth2 models **/
type Storage struct {
	clients   map[string]osin.Client
	authorize map[string]*osin.AuthorizeData
	access    map[string]*osin.AccessData
	refresh   map[string]string
}

type OACred struct {
	Key          *newdatastore.Key `json:"-" newdatastore:"-"`
	ID           int64             `json:"id"`
	ClientKey    string            `json:"client_key"`
	ClientSecret string            `json:"client_secret"`
	RedirectURI  string            `json:"redirect_uri"`
}

/** end oAuth2 models **/

//type Account holds the basic information for an attached account
type Account struct {
	Key     *newdatastore.Key `json:"-" newdatastore:"-"` //Locally cached key
	ID      string            `json:"id"`
	Created time.Time         `json:"created"` //When account was first created
	Name    string            `json:"name"`    //Name of account
	Slug    string            `json:"slug"`    //Unique slug
	ApiKey  string            `json:"apikey"`  //Generated API Key for this account // TODO - encrypt this
	Active  bool              `json:"active"`  //True if this account is active
}

type User struct {
	Key               *newdatastore.Key `json:"-" newdatastore:"-"`
	ID                int64             `json:"id"`
	Created           time.Time         `json:"created"`
	LastLogin         time.Time         `json:"lastLogin"`
	Username          string            `json:"username"`
	Email             string            `json:"email"`
	Password          string            `json:"password" newdatastore:"-"`
	Permission        string            `json:"permission"`
	EncryptedPassword []byte            `json:"-"`
	FirstName         string            `json:"firstName"`
	LastName          string            `json:"lastName"`
	AccountName       string            `json:"acc_key"`
}

type Recipe struct {
	Key       *newdatastore.Key `json:"-" newdatastore:"-"`
	ID        int64             `json:"id"`
	Created   time.Time         `json:"created"`
	Name      string            `json:"name"`
	Slug      string            `json:"slug"`
	ImgUrl    string            `json:"imgUrl"`
	CreatorID int64             `json:"creatorID"`
	TagIDs    []int64           `json:"tagIDs"`
}

type Tag struct {
	Key       *newdatastore.Key `json:"-" newdatastore:"-"`
	ID        int64             `json:"id"`
	Created   time.Time         `json:"created"`
	Name      string            `json:"name"`
	CreatorID int64             `json:"creatorID"`
}

type Rating struct {
	Key       *newdatastore.Key `json:"-" newdatastore:"-"`
	ID        int64             `json:"id"`
	Created   time.Time         `json:"created"`
	CreatorID int64             `json:"creatorID"`
	RecipeID  int64             `json:"recipeID"`
}

type Session struct {
	Key         string            `json:"key"` //Session Key provided for identification
	User        *newdatastore.Key `json:"-"`
	Account     *newdatastore.Key `json:"-"`           //Key to actual account
	Initialized time.Time         `json:"initialized"` //Time session was first created
	LastUsed    time.Time         `json:"lastUsed"`    //Last time session was used
	TTL         time.Duration     `json:"ttl"`         //How long should this session be valid after LastUsed
}

/** oAuth2 functions **/
func NewStorage( /*cred *OACred*/ ) *Storage {
	r := &Storage{
		clients:   make(map[string]osin.Client),
		authorize: make(map[string]*osin.AuthorizeData),
		access:    make(map[string]*osin.AccessData),
		refresh:   make(map[string]string),
	}

	//	r.clients[cred.ClientKey] = &osin.DefaultClient{
	//		Id:				cred.ClientKey,
	//		Secret: 		cred.ClientSecret,
	//		RedirectUri:	cred.RedirectURI,
	//	}

	r.clients["1234"] = &osin.DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "http://localhost:8080/appauth",
	}

	return r
}

func (s *Storage) Clone() osin.Storage { return s }
func (s *Storage) Close()              {}

func (s *Storage) GetClient(id string) (osin.Client, error) {
	fmt.Printf("GetClient: %s\n", id)
	if c, ok := s.clients[id]; ok {
		return c, nil
	}
	return nil, errors.New("Client not found")
}

func (s *Storage) SetClient(id string, client osin.Client) error {
	fmt.Printf("SetClient: %s\n", id)
	s.clients[id] = client
	return nil
}

func (s *Storage) SaveAuthorize(data *osin.AuthorizeData) error {
	fmt.Printf("SaveAuthorize: %s\n", data.Code)
	s.authorize[data.Code] = data
	return nil
}

func (s *Storage) LoadAuthorize(code string) (*osin.AuthorizeData, error) {
	fmt.Printf("LoadAuthorize: %s\n", code)
	if d, ok := s.authorize[code]; ok {
		return d, nil
	}
	return nil, errors.New("Authorize not found")
}

func (s *Storage) RemoveAuthorize(code string) error {
	fmt.Printf("RemoveAuthorize: %s\n", code)
	delete(s.authorize, code)
	return nil
}

func (s *Storage) SaveAccess(data *osin.AccessData) error {
	fmt.Printf("SaveAccess: %s\n", data.AccessToken)
	s.access[data.AccessToken] = data
	if data.RefreshToken != "" {
		s.refresh[data.RefreshToken] = data.AccessToken
	}
	return nil
}

func (s *Storage) LoadAccess(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadAccess: %s\n", code)
	if d, ok := s.access[code]; ok {
		return d, nil
	}
	return nil, errors.New("Access not found")
}

func (s *Storage) RemoveAccess(code string) error {
	fmt.Printf("RemoveAccess: %s\n", code)
	delete(s.access, code)
	return nil
}

func (s *Storage) LoadRefresh(code string) (*osin.AccessData, error) {
	fmt.Printf("LoadRefresh: %s\n", code)
	if d, ok := s.refresh[code]; ok {
		return s.LoadAccess(d)
	}
	return nil, errors.New("Refresh not found")
}

func (s *Storage) RemoveRefresh(code string) error {
	fmt.Printf("RemoveRefresh: %s\n", code)
	delete(s.refresh, code)
	return nil
}

/** end oAuth2 functions **/

// TODO - Utilize MarshalJSON to remove password
func (u *User) BeforeSave(ctx context.Context) {
	if u.Password != "" {
		pw := u.Password
		u.Password = ""
		encrypted, err := encrypt([]byte(pw))
		if err != nil {
			//			ctx.Errorf("Error encoding password: %v", err.Error())
			return
		}
		u.EncryptedPassword = encrypted
	}
	if u.Username == "" {
		if u.Email != "" {
			u.Username = u.Email
		} else {
			u.Username = fmt.Sprintf("%v%v", u.FirstName, u.LastName)
		}
	}
	// If we've already registered this call within an account, go ahead and assign said account to user
	/*	if acct, _ := GetAccount(ctx); acct != nil {
		u.AccountKey = acct.Key
	}*/
	if u.Created.IsZero() {
		u.Created = time.Now()
	}
}

func (u *User) GetKey(ctx context.Context) (key *newdatastore.Key) {
	if u.Key != nil {
		key = u.Key
	} else if u.ID == 0 {
		key = newdatastore.NewIncompleteKey(ctx, "User", nil)
	} else {
		key = newdatastore.NewKey(ctx, "User", "", u.ID, nil)
		u.Key = key
	}
	return
}

func (u *User) validatePassword(password string) bool {
	decrypted, err := decrypt(u.EncryptedPassword)
	if err != nil {
		return false
	}
	return bytes.Equal([]byte(password), decrypted)
}

// Validate a username and password, returning the appropriate user object is one is found
func AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	u := &User{
		Username: username,
		Password: password,
	}
	err := u.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Authenticate a user based on the current values for username and password
func (u *User) Authenticate(ctx context.Context) error {
	query := newdatastore.NewQuery("User").
		Filter("Username =", u.Username).
		Limit(1)

	// We only check account if it's already set, so don't worry about an error
	acct, _ := GetAccount(ctx)
	if acct != nil {
		query.Filter("Account =", acct.Key)
	}
	iter := query.Run(ctx)

	_, err := iter.Next(u)
	if err != nil {
		if err != newdatastore.Done {
			//			ctx.Errorf("Error loading user: %v", err.Error())
		}
		// If it's just a mismatch, keep going, likely just changed structure
		if _, ok := err.(*newdatastore.ErrFieldMismatch); !ok {
			return err
		}
	}

	if u.validatePassword(u.Password) {
		u.LastLogin = time.Now()
		Save(ctx, u)
		return nil
	}
	return InvalidPassword
}

// Rating methods
func (rating *Rating) GetKey(ctx context.Context) (key *newdatastore.Key) {
	if rating.Key != nil {
		key = rating.Key
	} else {
		key = newdatastore.NewKey(ctx, "Rating", "", 0, nil)
	}
	return
}

func (rating *Rating) BeforeSave(ctx context.Context) {
	rating.Created = time.Now()

	if rating.Key == nil {
		rating.GetKey(ctx)
	}
}

// Tag methods
func (tag *Tag) GetKey(ctx context.Context) (key *newdatastore.Key) {
	if tag.Key != nil {
		key = tag.Key
	} else {
		key = newdatastore.NewKey(ctx, "Tag", "", 0, nil)
	}
	return
}

func (tag *Tag) BeforeSave(ctx context.Context) {
	if tag.Name == "" {
		tag.Name = fmt.Sprintf("Tag-%v", rand.Int())
		tag.Created = time.Now()
	}
	if tag.Key == nil {
		tag.GetKey(ctx)
	}
}

// Recipe methods
func (recipe *Recipe) GetKey(ctx context.Context) (key *newdatastore.Key) {
	if recipe.Key != nil {
		key = recipe.Key
	} else {
		key = newdatastore.NewKey(ctx, "Recipe", recipe.Slug, 0, nil)
	}
	return
}

func (recipe *Recipe) BeforeSave(ctx context.Context) {
	if recipe.Name == "" {
		recipe.Name = fmt.Sprintf("Recipe-%v", rand.Int())
	}
	if recipe.Slug == "" {
		recipe.Slug = GenerateUniqueSlug(ctx, "Recipe", recipe.Name)
		recipe.Created = time.Now()
	}
	if recipe.Key == nil {
		recipe.GetKey(ctx)
	}
}

// func GetKey returns the newdatastore key for an account
// [TODO] - Want to migrate this to use ID's for key, not slug
func (acct *Account) GetKey(ctx context.Context) (key *newdatastore.Key) {
	if acct.Key != nil {
		key = acct.Key
	} else {
		key = newdatastore.NewKey(ctx, "Account", acct.Slug, 0, nil)
		acct.Key = key
	}
	return
}

// func BeforeSave is called as part of Save prior to storing in the newdatastore
// serves to set a default account name and slug, as well as ApiKey and Created timestamp
func (acct *Account) BeforeSave(ctx context.Context) {
	if acct.ID == "" {
		acct.ID = uuid.New()
	}
	if acct.Name == "" {
		acct.Name = fmt.Sprintf("Account-%v", rand.Int())
	}
	if acct.Slug == "" {
		acct.Slug = GenerateUniqueSlug(ctx, "Account", acct.Name)
		acct.Created = time.Now()
		h := md5.New()
		io.WriteString(h, uuid.New())
		apiKeyBytes := h.Sum(nil)
		acct.ApiKey = fmt.Sprintf("%x", apiKeyBytes)
	}
	if acct.Key == nil {
		acct.GetKey(ctx)
	}
}

func (acct *Account) Session(ctx context.Context) *Session {
	if session, err := GetSession(ctx); err == nil {
		return session
	}
	session, err := createSession(ctx, acct, nil)
	if err != nil {
		//		ctx.Errorf("Error creating session: %v", err.Error())
		return nil
	}
	return session
}

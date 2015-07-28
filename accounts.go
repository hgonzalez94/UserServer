// Package account handles the authentication and
// account creation flow for APIs
package main

import (
	"crypto/md5"
	//	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	//	"github.com/qedus/nds"

	"golang.org/x/net/context"
	newappengine "google.golang.org/appengine"
	newdatastore "google.golang.org/appengine/datastore"
	newmemcache "google.golang.org/appengine/memcache"
)

var (
	mockAccount *Account
)

// Mock the currently authenticated account
// Useful for testing and debugging
func MockAccount(acct *Account) {
	mockAccount = acct
}

// Get Session key from request, checking Headers first, then Cookies
func sessionKeyFromRequest(req *http.Request) (sessionKey string) {
	headerName := Headers["session"]
	sessionKey = req.Header.Get(headerName)
	if sessionKey == "" {
		// fall back on cookie if we can
		sessionCookie, err := req.Cookie(headerName)
		if err != nil {
			return
		}
		sessionKey = sessionCookie.Value
	}
	return
}

// GetAccount returns the currently authenticated account, or an error if no account
// has been authenticated for this request
func GetAccount(ctx context.Context) (*Account, error) {

	if mockAccount != nil {
		return mockAccount, nil
	}
	reqId := newappengine.RequestID(ctx)
	if acct, ok := authenticatedAccounts[reqId]; ok {
		return acct, nil
	}
	return nil, Unauthenticated
}

func GetUser(ctx context.Context) (*User, error) {
	reqId := newappengine.RequestID(ctx)
	if user, ok := authenticatedUsers[reqId]; ok {
		return user, nil
	}
	return nil, Unauthenticated
}

// GetAccountKey returns the newdatastore key for the current account, or an error if no account
// has been authenticated for this request
func GetAccountKey(ctx context.Context) (*newdatastore.Key, error) {
	acct, err := GetAccount(ctx)
	if err != nil {
		return nil, err
	}
	return acct.GetKey(ctx), nil
}

// GetSession takes an context.Context and returns the appropriate session
func GetSession(ctx context.Context) (session *Session, err error) {
	reqId := newappengine.RequestID(ctx)
	session, ok := authenticatedSessions[reqId]
	if ok {
		return
	}
	return nil, Unauthenticated
}

// GetContext returns acct namespaced context for the currently authenticated account
// Useful for multi-tenant applications
func GetContext(req *http.Request) (context.Context, error) {
	ctx := newappengine.NewContext(req)
	//acctKey, err := GetAccountKey(ctx)
	acct, err := GetAccount(ctx)
	if err != nil {
		if err != Unauthenticated {
			//			ctx.Errorf("[accounts/GetContext] %v", err.Error())
		}
		return nil, err
	}
	return newappengine.Namespace(ctx, acct.Slug)
}

func getSession(ctx context.Context, key string) (*Session, error) {
	if session, ok := sessionsMap[key]; ok {
		return session, nil
	}
	session := &Session{}
	_, err := newmemcache.Gob.Get(ctx, "session-"+key, session)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func storeSession(ctx context.Context, session *Session, acct *Account, user *User) {
	key := session.Key
	sessionsMap[key] = session
	sessionToAccount[session] = acct
	sessionToUser[session] = user
	i := &newmemcache.Item{
		Key:    "session-" + session.Key,
		Object: session,
	}
	err := newmemcache.Gob.Set(ctx, i)
	if err != nil {
		//		ctx.Errorf(err.Error())
	}
}

func sendSession(req *http.Request, rw http.ResponseWriter, session *Session) {
	sessionHeader := Headers["session"]
	sessionKey := session.Key

	var domain string
	if reqUrl, err := url.Parse(req.Header.Get("Origin")); err != nil {
		domain = reqUrl.Host
		// If domain includes port, slice it off
		if strings.Contains(domain, ":") {
			domainParts := strings.Split(domain, ":")
			domain = domainParts[0]
		}
	}
	cookie := &http.Cookie{
		Name:   sessionHeader,
		Value:  sessionKey,
		Domain: domain,
		Path:   "/",
	}

	rw.Header().Set(sessionHeader, sessionKey)
	rw.Header().Add("Access-Control-Expose-Headers", sessionHeader)

	http.SetCookie(rw, cookie)
}

func SendSession(req *http.Request, rw http.ResponseWriter, session *Session) {
	sendSession(req, rw, session)
}

func createSession(ctx context.Context, acct *Account, user *User) (*Session, error) {
	now := time.Now()
	h := md5.New()
	io.WriteString(h, fmt.Sprintf("%v-%d", acct.Slug, now.UnixNano()))
	hash := h.Sum(nil)
	acctKey := acct.GetKey(ctx)
	session := &Session{
		Key:         fmt.Sprintf("%x", hash),
		Account:     acctKey,
		Initialized: now,
		LastUsed:    now,
		TTL:         SessionTTL,
	}
	if user != nil {
		session.User = user.GetKey(ctx)
	}
	storeSession(ctx, session, acct, user)
	storeAuthenticatedRequest(ctx, acct, session, user)
	return session, nil
}

func CreateSession(ctx context.Context, acct *Account, user *User) (*Session, error) {
	return createSession(ctx, acct, user)
}

func storeAuthenticatedRequest(ctx context.Context, acct *Account, session *Session, user *User) {
	reqId := newappengine.RequestID(ctx)
	authenticatedAccounts[reqId] = acct
	authenticatedSessions[reqId] = session
	authenticatedUsers[reqId] = user
}

// ClearAuthenticatedRequest removes a request from the internal authentication mappings to both account and session
// called automatically after a request has been processed by AuthenticatedHandler and AuthenticatedFunc
func ClearAuthenticatedRequest(req *http.Request) {
	ctx := newappengine.NewContext(req)
	reqId := newappengine.RequestID(ctx)
	delete(authenticatedAccounts, reqId)
	delete(authenticatedSessions, reqId)
	delete(authenticatedUsers, reqId)
}

// Clears the session, optionally specified by a key, otherwise pulled from the current request
// Returns a bool for whether or not that session existed
func ClearSession(req *http.Request, sessionKey string) bool {
	ctx := newappengine.NewContext(req)
	if sessionKey == "" {
		sessionKey = sessionKeyFromRequest(req)
		if sessionKey == "" {
			return false
		}
	}
	newmemcache.Delete(ctx, "session-"+sessionKey)
	if session, ok := sessionsMap[sessionKey]; ok {
		delete(sessionsMap, sessionKey)

		if _, ok = sessionToAccount[session]; ok {
			delete(sessionToAccount, session)
		}

		return true
	}
	return false
}

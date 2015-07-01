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
//	"golang.org/x/oauth2"
//	"golang.org/x/oauth2/google"
//
//	newappengine "google.golang.org/appengine"
	newdatastore "google.golang.org/appengine/datastore"
//	newurlfetch "google.golang.org/appengine/urlfetch"

//	"appengine"
//	"appengine/datastore"
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

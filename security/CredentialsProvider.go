// Copyright 2023 GOM. All rights reserved.
// Since 13/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type CredentialsProvider interface {
	Authenticate(username, password string) (*User, error)
	Get(username string) *User
}

type CredentialsSource interface {
	CredentialsProvider
	Add(User) *User
	Delete(string) *User
}

type credentialEntry struct {
	password string
	user     User
}

type credentialsMap map[string]credentialEntry

func (scp credentialsMap) Get(username string) *User {
	if entry, found := scp[username]; found {
		return &entry.user
	}
	return nil
}

func (scp credentialsMap) Authenticate(username, password string) (*User, error) {
	if entry, found := scp[username]; found {
		if entry.password != password {
			return nil, errors.New("invalid password")
		}
		return &entry.user, nil
	}
	return nil, nil
}

type inMemoryCredentialsProvider struct {
	lock        sync.Mutex
	credentials credentialsMap
}

func (imcp *inMemoryCredentialsProvider) Get(username string) *User {
	imcp.lock.Lock()
	defer imcp.lock.Unlock()

	return imcp.credentials.Get(username)
}

func (imcp *inMemoryCredentialsProvider) Add(user User) *User {
	imcp.lock.Lock()
	defer imcp.lock.Unlock()

	existingUser := imcp.credentials.Get(user.Username)
	entry := credentialEntry{user: user}
	if strings.HasPrefix(user.Password, "md5:") {
		entry.password = user.Password[4:]
	} else {
		md5Sum := md5.Sum([]byte(user.Password))
		entry.password = base64.StdEncoding.EncodeToString(md5Sum[:])
	}
	entry.user.Password = ""
	imcp.credentials[user.Username] = entry

	return existingUser
}

func (imcp *inMemoryCredentialsProvider) Delete(username string) *User {
	imcp.lock.Lock()
	defer imcp.lock.Unlock()

	if existingUser := imcp.credentials.Get(username); existingUser != nil {
		delete(imcp.credentials, username)
		return existingUser
	}

	return nil
}

func (imcp *inMemoryCredentialsProvider) Authenticate(username, password string) (*User, error) {
	imcp.lock.Lock()
	defer imcp.lock.Unlock()

	return imcp.credentials.Authenticate(username, password)
}

func DefaultCredentialsProvider(users ...User) CredentialsProvider {
	if len(users) == 0 {
		username := uuid.NewString()
		password := uuid.NewString()
		fmt.Println("Generated credentials:", username, password)
		users = []User{{Username: username, Password: password}}
	}

	provider := make(credentialsMap)
	for _, user := range users {
		entry := credentialEntry{user: user}
		if strings.HasPrefix(user.Password, "md5:") {
			entry.password = user.Password[4:]
		} else {
			md5Sum := md5.Sum([]byte(user.Password))
			entry.password = base64.StdEncoding.EncodeToString(md5Sum[:])
		}
		entry.user.Password = ""
		provider[user.Username] = entry
	}
	return provider
}

func InMemoryCredentialsProvider(credentials ...User) CredentialsSource {
	provider := &inMemoryCredentialsProvider{credentials: make(credentialsMap)}

	for _, credential := range credentials {
		provider.Add(credential)
	}

	return provider
}

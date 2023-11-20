// Copyright 2023 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/gomatbase/go-we/security"
)

func TestDefaultCredentialsProvider(t *testing.T) {
	t.Run("Test generated credentials", func(t *testing.T) {
		savedOutput := os.Stdout
		reader, writer, e := os.Pipe()
		if e != nil {
			panic(e)
		}
		os.Stdout = writer

		provider := security.DefaultCredentialsProvider()
		// read the credentials, which are written to stdout in the form "Generated credentials: username password"
		scanner := bufio.NewScanner(reader)
		scanner.Scan()
		parts := strings.Split(scanner.Text(), " ")
		username := parts[2]
		password := parts[3]

		if _, e = provider.Authenticate(username, password); e == nil {
			t.Errorf("Error authenticating generated credentials. Username %s authenticated with clear password %s", username, password)
		}

		md5Sum := md5.Sum([]byte(password))
		password = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username, password); e != nil {
			t.Errorf("Error authenticating generated credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating generated credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating generated credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		os.Stdout = savedOutput
	})
	t.Run("Test Provided credentials (plain)", func(t *testing.T) {
		username := "test"
		password := "password"

		provider := security.DefaultCredentialsProvider(security.User{Username: username, Password: password})

		if _, e := provider.Authenticate(username, password); e == nil {
			t.Errorf("Error authenticating provided credentials. Username %s authenticated with clear password %s", username, password)
		}

		md5Sum := md5.Sum([]byte(password))
		password = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username, password); e != nil {
			t.Errorf("Error authenticating provided credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

	})
	t.Run("Test Provided credentials (digested)", func(t *testing.T) {
		username := "test"
		password := "password"

		md5Sum := md5.Sum([]byte(password))
		digest := "md5:" + base64.StdEncoding.EncodeToString(md5Sum[:])

		provider := security.DefaultCredentialsProvider(security.User{Username: username, Password: digest})

		if _, e := provider.Authenticate(username, password); e == nil {
			t.Errorf("Error authenticating provided digested credentials. Username %s authenticated with clear password %s", username, password)
		}

		if user, e := provider.Authenticate(username, digest[4:]); e != nil {
			t.Errorf("Error authenticating provided digested credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided digested credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided digested credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

	})
	t.Run("Test Provided multiple credentials", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		md5Sum := md5.Sum([]byte(password2))
		digest := "md5:" + base64.StdEncoding.EncodeToString(md5Sum[:])

		provider := security.DefaultCredentialsProvider(security.User{Username: username1, Password: password1}, security.User{Username: username2, Password: digest})

		if _, e := provider.Authenticate(username1, password1); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with clear password %s", username1, password1)
		}
		if _, e := provider.Authenticate(username1, digest[4:]); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with incorrect password %s", username1, digest[4:])
		}

		md5Sum = md5.Sum([]byte(password1))
		password1 = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username1, password1); e != nil {
			t.Errorf("Error authenticating multiple credentials (plain). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (plain). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating multiple credentials (plain). User found doesn't match username %s vs %s", user.Username, username1)
		}

		if user, e := provider.Authenticate(username2, digest[4:]); e != nil {
			t.Errorf("Error authenticating multiple credentials (digested). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (digested). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating multiple credentials (digested). User found doesn't match username %s vs %s", user.Username, username2)
		}

	})
}

func TestInMemoryCredentialsProvider(t *testing.T) {
	t.Run("Test Provided credentials (plain)", func(t *testing.T) {
		username := "test"
		password := "password"

		provider := security.InMemoryCredentialsProvider(security.User{Username: username, Password: password})

		if _, e := provider.Authenticate(username, password); e == nil {
			t.Errorf("Error authenticating provided credentials. Username %s authenticated with clear password %s", username, password)
		}

		md5Sum := md5.Sum([]byte(password))
		password = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username, password); e != nil {
			t.Errorf("Error authenticating provided credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

	})
	t.Run("Test Provided credentials (digested)", func(t *testing.T) {
		username := "test"
		password := "password"

		md5Sum := md5.Sum([]byte(password))
		digest := "md5:" + base64.StdEncoding.EncodeToString(md5Sum[:])

		provider := security.InMemoryCredentialsProvider(security.User{Username: username, Password: digest})

		if _, e := provider.Authenticate(username, password); e == nil {
			t.Errorf("Error authenticating provided digested credentials. Username %s authenticated with clear password %s", username, password)
		}

		if user, e := provider.Authenticate(username, digest[4:]); e != nil {
			t.Errorf("Error authenticating provided digested credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided digested credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided digested credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

	})
	t.Run("Test Provided multiple credentials", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		md5Sum := md5.Sum([]byte(password2))
		digest := "md5:" + base64.StdEncoding.EncodeToString(md5Sum[:])

		provider := security.InMemoryCredentialsProvider(security.User{Username: username1, Password: password1}, security.User{Username: username2, Password: digest})

		if _, e := provider.Authenticate(username1, password1); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with clear password %s", username1, password1)
		}
		if _, e := provider.Authenticate(username1, digest[4:]); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with incorrect password %s", username1, digest[4:])
		}

		md5Sum = md5.Sum([]byte(password1))
		password1 = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username1, password1); e != nil {
			t.Errorf("Error authenticating multiple credentials (plain). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (plain). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating multiple credentials (plain). User found doesn't match username %s vs %s", user.Username, username1)
		}

		if user, e := provider.Authenticate(username2, digest[4:]); e != nil {
			t.Errorf("Error authenticating multiple credentials (digested). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (digested). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating multiple credentials (digested). User found doesn't match username %s vs %s", user.Username, username2)
		}

	})
	t.Run("Test credentials CRUD", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		md5Sum := md5.Sum([]byte(password2))
		digest := "md5:" + base64.StdEncoding.EncodeToString(md5Sum[:])

		provider := security.InMemoryCredentialsProvider()
		provider.Add(security.User{Username: username1, Password: password1})

		if _, e := provider.Authenticate(username1, password1); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with clear password %s", username1, password1)
		}
		if _, e := provider.Authenticate(username1, digest[4:]); e == nil {
			t.Errorf("Error authenticating multiple credentials. Username %s authenticated with incorrect password %s", username1, digest[4:])
		}
		if user, e := provider.Authenticate(username2, digest[4:]); e != nil {
			t.Errorf("Error authenticating multiple credentials. Non existing username returning error %v", e)
		} else if user != nil {
			t.Errorf("Error authenticating multiple credentials. Non existing username %s authenticated", username2)
		}

		md5Sum = md5.Sum([]byte(password1))
		password1 = base64.StdEncoding.EncodeToString(md5Sum[:])

		if user, e := provider.Authenticate(username1, password1); e != nil {
			t.Errorf("Error authenticating multiple credentials (plain). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (plain). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating multiple credentials (plain). User found doesn't match username %s vs %s", user.Username, username1)
		}

		provider.Add(security.User{Username: username2, Password: digest})

		if user, e := provider.Authenticate(username2, digest[4:]); e != nil {
			t.Errorf("Error authenticating multiple credentials (digested). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (digested). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating multiple credentials (digested). User found doesn't match username %s vs %s", user.Username, username2)
		}

		if user := provider.Get("something"); user != nil {
			t.Errorf("Error getting non existing user. User found %v", user)
		} else if user = provider.Get(username1); user == nil {
			t.Error("Error getting existing user. No user found")
		} else if user.Username != username1 {
			t.Errorf("Error getting existing user. User found doesn't match username %s vs %s", user.Username, username1)
		}

		if user := provider.Delete("something"); user != nil {
			t.Errorf("Error deleting non existing user. User found %v", user)
		} else if user = provider.Delete(username1); user == nil {
			t.Error("Error deleting existing user. No user found")
		}

		if user := provider.Get(username1); user != nil {
			t.Errorf("Error getting deleted user. User found %v", user)
		} else if user = provider.Get(username2); user == nil {
			t.Error("Error getting existing user. No user found")
		} else if user.Username != username2 {
			t.Errorf("Error getting existing user. User found doesn't match username %s vs %s", user.Username, username2)
		}

		if user, e := provider.Authenticate(username1, password1); e != nil {
			t.Errorf("Error authenticating deleted credentials. %v", e)
		} else if user != nil {
			t.Errorf("Error authenticating deleted credentials. User found : %v", user)
		} else if user, e = provider.Authenticate(username2, digest[4:]); e != nil {
			t.Errorf("Error authenticating existing credentials after deleting other credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating existing credentials after deleting other credentials. No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating existing credentials after deleting other credentials. User found doesn't match username %s vs %s", user.Username, username2)
		}

	})
}

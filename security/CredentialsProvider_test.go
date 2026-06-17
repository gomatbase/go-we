// Copyright 2023-2026 GOM. All rights reserved.
// Since 14/11/2023 By GOM
// Licensed under MIT License

package security_test

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/gomatbase/go-we/security"
	"golang.org/x/crypto/bcrypt"
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

		// Test with plaintext password (should succeed now)
		if user, e := provider.Authenticate(context.Background(), username, password); e != nil {
			t.Errorf("Error authenticating generated credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating generated credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating generated credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		// Test with wrong password (should fail)
		if _, e := provider.Authenticate(context.Background(), username, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username)
		}

		os.Stdout = savedOutput
	})
	t.Run("Test Provided credentials (plain)", func(t *testing.T) {
		username := "test"
		password := "password"

		provider := security.DefaultCredentialsProvider(security.User{Username: username, Password: password})

		// Test with plaintext password (should succeed)
		if user, e := provider.Authenticate(context.Background(), username, password); e != nil {
			t.Errorf("Error authenticating provided credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		// Test with wrong password (should fail)
		if _, e := provider.Authenticate(context.Background(), username, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username)
		}
	})
	t.Run("Test Provided credentials (pre-hashed)", func(t *testing.T) {
		username := "test"
		password := "password"

		// Generate a bcrypt hash and prefix it with "bcrypt:"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		bcryptPrefixed := "bcrypt:" + string(hashedPassword)

		provider := security.DefaultCredentialsProvider(security.User{Username: username, Password: bcryptPrefixed})

		// Test with plaintext password (should succeed)
		if user, e := provider.Authenticate(context.Background(), username, password); e != nil {
			t.Errorf("Error authenticating provided pre-hashed credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided pre-hashed credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided pre-hashed credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		// Test with wrong password (should fail)
		if _, e := provider.Authenticate(context.Background(), username, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username)
		}
	})
	t.Run("Test Provided multiple credentials", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		// Create pre-hashed password for user2
		hashedPassword2, _ := bcrypt.GenerateFromPassword([]byte(password2), bcrypt.DefaultCost)
		bcryptPrefixed := "bcrypt:" + string(hashedPassword2)

		provider := security.DefaultCredentialsProvider(
			security.User{Username: username1, Password: password1},
			security.User{Username: username2, Password: bcryptPrefixed},
		)

		// Test user1 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username1, password1); e != nil {
			t.Errorf("Error authenticating multiple credentials (user1). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (user1). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating multiple credentials (user1). User found doesn't match username %s vs %s", user.Username, username1)
		}

		// Test user2 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username2, password2); e != nil {
			t.Errorf("Error authenticating multiple credentials (user2). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (user2). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating multiple credentials (user2). User found doesn't match username %s vs %s", user.Username, username2)
		}

		// Test wrong password for user1
		if _, e := provider.Authenticate(context.Background(), username1, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username1)
		}

		// Test wrong password for user2
		if _, e := provider.Authenticate(context.Background(), username2, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username2)
		}
	})
}

func TestInMemoryCredentialsProvider(t *testing.T) {
	t.Run("Test Provided credentials (plain)", func(t *testing.T) {
		username := "test"
		password := "password"

		provider := security.InMemoryCredentialsProvider(security.User{Username: username, Password: password})

		// Test with plaintext password (should succeed)
		if user, e := provider.Authenticate(context.Background(), username, password); e != nil {
			t.Errorf("Error authenticating provided credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		// Test with wrong password (should fail)
		if _, e := provider.Authenticate(context.Background(), username, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username)
		}
	})
	t.Run("Test Provided credentials (pre-hashed)", func(t *testing.T) {
		username := "test"
		password := "password"

		// Generate a bcrypt hash and prefix it with "bcrypt:"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		bcryptPrefixed := "bcrypt:" + string(hashedPassword)

		provider := security.InMemoryCredentialsProvider(security.User{Username: username, Password: bcryptPrefixed})

		// Test with plaintext password (should succeed)
		if user, e := provider.Authenticate(context.Background(), username, password); e != nil {
			t.Errorf("Error authenticating provided pre-hashed credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating provided pre-hashed credentials. No user found")
		} else if user.Username != username {
			t.Errorf("Error authenticating provided pre-hashed credentials. User found doesn't match username %s vs %s", user.Username, username)
		}

		// Test with wrong password (should fail)
		if _, e := provider.Authenticate(context.Background(), username, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username)
		}
	})
	t.Run("Test Provided multiple credentials", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		// Create pre-hashed password for user2
		hashedPassword2, _ := bcrypt.GenerateFromPassword([]byte(password2), bcrypt.DefaultCost)
		bcryptPrefixed := "bcrypt:" + string(hashedPassword2)

		provider := security.InMemoryCredentialsProvider(
			security.User{Username: username1, Password: password1},
			security.User{Username: username2, Password: bcryptPrefixed},
		)

		// Test user1 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username1, password1); e != nil {
			t.Errorf("Error authenticating multiple credentials (user1). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (user1). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating multiple credentials (user1). User found doesn't match username %s vs %s", user.Username, username1)
		}

		// Test user2 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username2, password2); e != nil {
			t.Errorf("Error authenticating multiple credentials (user2). %v", e)
		} else if user == nil {
			t.Error("Error authenticating multiple credentials (user2). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating multiple credentials (user2). User found doesn't match username %s vs %s", user.Username, username2)
		}

		// Test wrong password for user1
		if _, e := provider.Authenticate(context.Background(), username1, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username1)
		}

		// Test wrong password for user2
		if _, e := provider.Authenticate(context.Background(), username2, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username2)
		}
	})
	t.Run("Test credentials CRUD", func(t *testing.T) {
		username1 := "test"
		password1 := "password"
		username2 := "test2"
		password2 := "second password"

		provider := security.InMemoryCredentialsProvider()
		provider.Add(security.User{Username: username1, Password: password1})

		// Test user1 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username1, password1); e != nil {
			t.Errorf("Error authenticating credentials (user1). %v", e)
		} else if user == nil {
			t.Error("Error authenticating credentials (user1). No user found")
		} else if user.Username != username1 {
			t.Errorf("Error authenticating credentials (user1). User found doesn't match username %s vs %s", user.Username, username1)
		}

		// Test wrong password for user1
		if _, e := provider.Authenticate(context.Background(), username1, "wrongpassword"); e == nil {
			t.Errorf("Error: username %s should not authenticate with wrong password", username1)
		}

		// Test non-existing user
		if user, e := provider.Authenticate(context.Background(), username2, password2); e != nil {
			t.Errorf("Error authenticating non-existing credentials. Non existing username returning error %v", e)
		} else if user != nil {
			t.Errorf("Error authenticating non-existing credentials. Non existing username %s authenticated", username2)
		}

		// Create pre-hashed password for user2
		hashedPassword2, _ := bcrypt.GenerateFromPassword([]byte(password2), bcrypt.DefaultCost)
		bcryptPrefixed := "bcrypt:" + string(hashedPassword2)
		provider.Add(security.User{Username: username2, Password: bcryptPrefixed})

		// Test user2 with plaintext password
		if user, e := provider.Authenticate(context.Background(), username2, password2); e != nil {
			t.Errorf("Error authenticating credentials (user2). %v", e)
		} else if user == nil {
			t.Error("Error authenticating credentials (user2). No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating credentials (user2). User found doesn't match username %s vs %s", user.Username, username2)
		}

		// Test Get functionality
		if user := provider.Get("something"); user != nil {
			t.Errorf("Error getting non existing user. User found %v", user)
		} else if user = provider.Get(username1); user == nil {
			t.Error("Error getting existing user. No user found")
		} else if user.Username != username1 {
			t.Errorf("Error getting existing user. User found doesn't match username %s vs %s", user.Username, username1)
		}

		// Test Delete functionality
		if user := provider.Delete("something"); user != nil {
			t.Errorf("Error deleting non existing user. User found %v", user)
		} else if user = provider.Delete(username1); user == nil {
			t.Error("Error deleting existing user. No user found")
		}

		// Verify user1 is deleted
		if user := provider.Get(username1); user != nil {
			t.Errorf("Error getting deleted user. User found %v", user)
		}

		// Verify user2 still exists
		if user := provider.Get(username2); user == nil {
			t.Error("Error getting existing user. No user found")
		} else if user.Username != username2 {
			t.Errorf("Error getting existing user. User found doesn't match username %s vs %s", user.Username, username2)
		}

		// Test authentication after deletion
		if user, e := provider.Authenticate(context.Background(), username1, password1); e != nil {
			t.Errorf("Error authenticating deleted credentials. %v", e)
		} else if user != nil {
			t.Errorf("Error authenticating deleted credentials. User found : %v", user)
		}

		// Test user2 still authenticates
		if user, e := provider.Authenticate(context.Background(), username2, password2); e != nil {
			t.Errorf("Error authenticating existing credentials after deleting other credentials. %v", e)
		} else if user == nil {
			t.Error("Error authenticating existing credentials after deleting other credentials. No user found")
		} else if user.Username != username2 {
			t.Errorf("Error authenticating existing credentials after deleting other credentials. User found doesn't match username %s vs %s", user.Username, username2)
		}
	})
}

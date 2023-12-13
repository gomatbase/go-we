// Copyright 2023 GOM. All rights reserved.
// Since 13/11/2023 By GOM
// Licensed under MIT License

package security

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	html_template "html/template"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/gomatbase/go-we"
	"github.com/gomatbase/go-we/events"
)

const (
	DefaultTemplate = "<!DOCTYPE html>" +
		"<html lang=\"en\">" +
		"<head>" +
		"    <meta charset=\"UTF-8\">" +
		"    <title>{{.Title}}</title>" +
		"</head>" +
		"<body>" +
		"<h2>{{.Header}}</h2>" +
		"{{.Error}}" +
		"<form action=\"{{.Action}}\" method=\"post\">" +
		"    <label for=\"{{.UsernameField}}\">{{.UsernameLabel}}</label><br>" +
		"    <input type=\"text\" id=\"{{.UsernameField}}\" name=\"{{.UsernameField}}\"><br>" +
		"    <label for=\"{{.PasswordField}}\">{{.PasswordLabel}}</label><br>" +
		"    <input type=\"password\" id=\"{{.PasswordField}}\" name=\"{{.PasswordField}}\"><br><br>" +
		"    <input type=\"hidden\" id=\"target\" name=\"{{.TargetField}}\" value=\"{{.Target}}\"><br><br>" +
		"    <input type=\"submit\" value=\"{{.SubmitLabel}}\">" +
		"</form>" +
		"</body>" +
		"</html>"

	DefaultAction          = "/login"
	DefaultTitle           = "Login"
	DefaultHeader          = "Login"
	DefaultUsernameField   = "username"
	DefaultPasswordField   = "password"
	DefaultTargetField     = "target"
	DefaultSubmitLabel     = "Login"
	DefaultUsernameLabel   = "Username:"
	DefaultPasswordLabel   = "Password:"
	DefaultErrorExpression = "<h1>Error: {{.Error}}</h1>"
)

type LoginForm interface {
	Generate(error string, target string) string
	Configuration() *LoginFormConfiguration
}

type LoginFormConfiguration struct {
	Action        string
	UsernameLabel string
	PasswordLabel string
	SubmitLabel   string
	UsernameField string
	PasswordField string
	TargetField   string
	Target        string
	Title         string
	Header        string
	Error         string
}

type loginRenderingParameters struct {
	Target string
	Error  string
}

type loginForm struct {
	template      *html_template.Template
	staticForm    string
	configuration *LoginFormConfiguration
}

func (lf *loginForm) Generate(error string, target string) string {
	if lf.template != nil {
		// a template is defined, so we expect a target
		buffer := &bytes.Buffer{}
		if e := lf.template.Execute(buffer, loginRenderingParameters{Target: target, Error: error}); e == nil {
			return buffer.String()
		}
	}
	return lf.staticForm
}

func (lf *loginForm) Configuration() *LoginFormConfiguration {
	return lf.configuration
}

func CustomLoginForm(configuration LoginFormConfiguration, customTemplate string) LoginForm {
	t, e := template.New("loginForm").Parse(customTemplate)
	if e != nil {
		panic(e)
	}

	configuration.Target = "{{.Target}}"
	if len(configuration.Error) != 0 {
		configuration.Error = fmt.Sprintf("{{if .Error}}%s{{end}}", configuration.Error)
	}
	buffer := &bytes.Buffer{}

	// at this stage it means the template is valid. Can't see why execution would fail with an in-memory buffer (aside from
	// memory issues which should panic anyway). Ignoring error.
	_ = t.Execute(buffer, configuration)

	// we parse the resulting template to see if it's still valid
	form := &loginForm{staticForm: buffer.String(), configuration: &configuration}
	formTemplate, e := html_template.New("loginForm").Parse(form.staticForm)
	if e != nil {
		panic(e)
	}

	if strings.Index(form.staticForm, ".Error}}") >= 0 || strings.Index(form.staticForm, ".Target}}") >= 0 {
		form.template = formTemplate
	}

	return form
}

func DefaultLoginForm(configuration LoginFormConfiguration) LoginForm {
	if len(configuration.Action) == 0 {
		configuration.Action = DefaultAction
	}
	if len(configuration.Title) == 0 {
		configuration.Title = DefaultTitle
	}
	if len(configuration.Header) == 0 {
		configuration.Header = DefaultHeader
	}
	if len(configuration.UsernameField) == 0 {
		configuration.UsernameField = DefaultUsernameField
	}
	if len(configuration.PasswordField) == 0 {
		configuration.PasswordField = DefaultPasswordField
	}
	if len(configuration.TargetField) == 0 {
		configuration.TargetField = DefaultTargetField
	}
	if len(configuration.UsernameLabel) == 0 {
		configuration.UsernameLabel = DefaultUsernameLabel
	}
	if len(configuration.PasswordLabel) == 0 {
		configuration.PasswordLabel = DefaultPasswordLabel
	}
	if len(configuration.SubmitLabel) == 0 {
		configuration.SubmitLabel = DefaultSubmitLabel
	}
	if len(configuration.Error) == 0 {
		configuration.Error = DefaultErrorExpression
	}
	return CustomLoginForm(configuration, DefaultTemplate)
}

type LoginFormAuthenticationProviderBuilder interface {
	Realm(string) BasicAuthenticationProviderBuilder
	CredentialsProvider(CredentialsProvider) BasicAuthenticationProviderBuilder
	LoginForm(LoginForm) LoginFormAuthenticationProviderBuilder
	Required(bool) LoginFormAuthenticationProviderBuilder
	RedirectToForm(bool) LoginFormAuthenticationProviderBuilder
	DefaultAuthenticatedRedirectionPath(string) LoginFormAuthenticationProviderBuilder
	Build() AuthenticationProvider
}

func LoginFormAuthenticationProvider(users ...User) LoginFormAuthenticationProviderBuilder {
	builder := &loginFormAuthenticationProviderBuilder{provider: &loginFormAuthenticationProvider{}}
	if len(users) > 0 {
		builder.provider.credentialsProvider = DefaultCredentialsProvider(users...)
	}
	return builder
}

type loginFormAuthenticationProvider struct {
	realm                  string
	loginPath              string
	loginForm              LoginForm
	defaultRedirectPath    string
	redirect               bool
	required               bool
	credentialsProvider    CredentialsProvider
	loginFormConfiguration *LoginFormConfiguration
}

func (lfap *loginFormAuthenticationProvider) Authenticate(headers http.Header, scope we.RequestScope) (*User, error) {
	// let's see if it's for the login path
	request := scope.Request()
	if request.URL.Path == lfap.loginPath {
		// Let's see if it's a submission
		if request.Method == http.MethodPost {
			// it is... let's first quickly check if it's small enough to be a submission form, and if not, let's simply unauthorize it
			if request.ContentLength > 1024 {
				// such a submission would come out of another source and not from the provider, so... drop the target
				return nil, events.BadRequestError.WithPayload("application/html", []byte(lfap.loginForm.Generate("Invalid login submission", "")))
			}
			if e := request.ParseForm(); e != nil {
				// target would have come from the form, and parsing the form failed, so... drop the target
				return nil, events.UnauthorizedError.WithPayload("application/html", []byte(lfap.loginForm.Generate(e.Error(), "")))
			}
			username := request.PostForm.Get(lfap.loginFormConfiguration.UsernameField)
			password := request.PostForm.Get(lfap.loginFormConfiguration.PasswordField)

			md5Sum := md5.Sum([]byte(password))
			if user, e := lfap.credentialsProvider.Authenticate(username, base64.StdEncoding.EncodeToString(md5Sum[:])); e != nil {
				return nil, events.UnauthorizedError.WithPayload("application/html", []byte(lfap.loginForm.Generate(e.Error(), request.PostForm.Get(lfap.loginFormConfiguration.TargetField))))
			} else if user == nil {
				return nil, events.UnauthorizedError.WithPayload("application/html", []byte(lfap.loginForm.Generate("Invalid credentials", request.PostForm.Get(lfap.loginFormConfiguration.TargetField))))
			} else {
				return user, nil
			}
		} else if request.Method == http.MethodGet {
			// It's a get, supply the login form
			target := scope.Parameter(lfap.loginFormConfiguration.TargetField)
			if len(target) == 0 {
				target = lfap.defaultRedirectPath
			}
			return nil, events.OKInterruption.WithPayload("application/html", []byte(lfap.loginForm.Generate("", target)))
		}
	}

	// it's not a call to login itself, let's see what kind of behaviour is expected
	if lfap.required {
		// authentication is required, let's present the login form
		if lfap.redirect {
			// client should be redirected to the login form

			if request.Method != http.MethodGet {
				// Makes no sense to make a final redirect for any method other than GET
				headers.Add("Location", fmt.Sprintf("%s://%s%s", request.URL.Scheme, request.URL.Host, lfap.loginPath))
			} else {
				headers.Add("Location", fmt.Sprintf("%s://%s%s?%s=%s", request.URL.Scheme, request.URL.Host, lfap.loginPath, lfap.loginFormConfiguration.TargetField, url.PathEscape(request.URL.Path)))
			}

			return nil, events.FoundRedirect
		}

		// no redirect, let's return the login form
		target := request.URL.Path
		if request.Method != http.MethodGet {
			target = lfap.defaultRedirectPath
		}
		return nil, events.UnauthorizedError.WithPayload("application/html", []byte(lfap.loginForm.Generate("", target)))
	}

	// authentication is not required, no user and no error
	return nil, nil
}

func (lfap *loginFormAuthenticationProvider) Realm() string {
	return lfap.realm
}

func (lfap *loginFormAuthenticationProvider) IsValid(user *User) bool {
	if user == nil {
		return false
	}
	return lfap.credentialsProvider.Get(user.Username) != nil
}

func (lfap *loginFormAuthenticationProvider) Challenge() string {
	return ""
}

func (lfap *loginFormAuthenticationProvider) Endpoints() []string {
	return []string{lfap.loginPath}
}

type loginFormAuthenticationProviderBuilder struct {
	credentialsProvider CredentialsProvider
	provider            *loginFormAuthenticationProvider
}

func (lfapb *loginFormAuthenticationProviderBuilder) Required(required bool) LoginFormAuthenticationProviderBuilder {
	lfapb.provider.required = required
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) RedirectToForm(redirect bool) LoginFormAuthenticationProviderBuilder {
	lfapb.provider.redirect = redirect
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) DefaultAuthenticatedRedirectionPath(redirectPath string) LoginFormAuthenticationProviderBuilder {
	lfapb.provider.defaultRedirectPath = redirectPath
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) LoginForm(form LoginForm) LoginFormAuthenticationProviderBuilder {
	lfapb.provider.loginForm = form
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) Realm(realm string) BasicAuthenticationProviderBuilder {
	lfapb.provider.realm = realm
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) CredentialsProvider(credentialsProvider CredentialsProvider) BasicAuthenticationProviderBuilder {
	lfapb.provider.credentialsProvider = credentialsProvider
	return lfapb
}

func (lfapb *loginFormAuthenticationProviderBuilder) Build() AuthenticationProvider {
	if lfapb.provider.credentialsProvider == nil {
		panic("no credentials provider")
	}
	if lfapb.provider.loginForm == nil {
		lfapb.provider.loginForm = DefaultLoginForm(LoginFormConfiguration{})
	}
	lfapb.provider.loginFormConfiguration = lfapb.provider.loginForm.Configuration()
	if parsedActionUrl, e := url.Parse(lfapb.provider.loginFormConfiguration.Action); e != nil {
		// errors should result in panics as they are not meant for recoverable runtime failures
		panic(e)
	} else {
		lfapb.provider.loginPath = parsedActionUrl.Path
	}
	if len(lfapb.provider.realm) == 0 {
		lfapb.provider.realm = "form"
	}
	if len(lfapb.provider.defaultRedirectPath) == 0 {
		lfapb.provider.defaultRedirectPath = "/"
	}
	return lfapb.provider
}

package test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gomatbase/csn"
)

var (
	InvalidUrlError = csn.Error("invalid url")
)

type HttpRequest struct {
	url        string
	header     http.Header
	tlsOptions *tls.Config
	e          error
	content    io.Reader
}

func Request(urlComponents ...string) *HttpRequest {
	result := &HttpRequest{header: http.Header{}}

	components := len(urlComponents)
	if urlComponents == nil || components == 0 {
		result.e = InvalidUrlError
		return result
	}

	url := urlComponents[0]
	lenComponent := len(url)
	if lenComponent == 0 {
		result.e = InvalidUrlError
		return result
	}
	if url[lenComponent-1] == '/' {
		url = url[:lenComponent-1]
	}

	for i := 1; i < components; i++ {
		if len(urlComponents[i]) == 0 {
			result.e = InvalidUrlError
			return result
		}
		if urlComponents[i][0] != '/' {
			url = url + "/"
		}
		url = url + urlComponents[i]
	}

	result.url = url
	return result
}

func (r *HttpRequest) WithAuthorization(authorization string) *HttpRequest {
	r.header.Set("Authorization", authorization)
	return r
}

func (r *HttpRequest) WithBearerToken(authorization string) *HttpRequest {
	r.header.Set("Authorization", "Bearer "+authorization)
	return r
}

func (r *HttpRequest) Accepting(mimeType string) *HttpRequest {
	r.header.Set("Accept", mimeType)
	return r
}

func (r *HttpRequest) Sending(mimeType string) *HttpRequest {
	r.header.Set("Content-type", mimeType)
	return r
}

func (r *HttpRequest) WithHeader(key, value string) *HttpRequest {
	r.header.Set(key, value)
	return r
}

func (r *HttpRequest) IgnoringSsl(ignore bool) *HttpRequest {
	r.transport().InsecureSkipVerify = ignore
	return r
}

func (r *HttpRequest) WithContent(content []byte) *HttpRequest {
	r.content = bytes.NewReader(content)
	return r
}

func (r *HttpRequest) DoWithResponse(method string) (*http.Response, error) {
	return r.DoWithTimedOutResponse(0, method)
}

func (r *HttpRequest) DoWithTimedOutResponse(timeout time.Duration, method string) (*http.Response, error) {
	if r.e != nil {
		return nil, r.e
	}

	request, e := http.NewRequest(method, r.url, r.content)
	if e != nil {
		return nil, e
	}

	client := http.Client{}
	if r.tlsOptions != nil {
		client.Transport = &http.Transport{TLSClientConfig: r.tlsOptions}
	}
	if timeout > 0 {
		client.Timeout = timeout
	}

	request.Header = r.header

	response, e := client.Do(request)
	if e != nil {
		return nil, e
	}

	return response, nil
}

func (r *HttpRequest) Do(method string) ([]byte, error) {
	response, e := r.DoWithResponse(method)
	if e != nil {
		return nil, e
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusBadRequest {
		body, e := io.ReadAll(response.Body)
		return body, errors.Join(fmt.Errorf("failed request: %v", response.Status), e)
	}

	body, e := io.ReadAll(response.Body)
	if e != nil {
		return nil, e
	}
	return body, nil
}

func (r *HttpRequest) Get() ([]byte, error) {
	return r.Do(http.MethodGet)
}

func (r *HttpRequest) transport() *tls.Config {
	if r.tlsOptions == nil {
		r.tlsOptions = &tls.Config{}
	}
	return r.tlsOptions
}

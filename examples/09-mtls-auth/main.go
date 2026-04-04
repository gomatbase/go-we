// Copyright 2026 GOM. All rights reserved.
// Licensed under MIT License

package main

import (
	"fmt"
	"net/http"

	"github.com/gomatbase/go-we"
)

func main() {
	engine := we.New()

	// Information page about mTLS
	engine.Handle("/", func(w http.ResponseWriter, scope we.RequestScope) error {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<h1>Mutual TLS (mTLS) Authentication Example</h1>
			
			<h2>What is mTLS?</h2>
			<p>Mutual TLS authentication requires both the client and server to authenticate each other using X.509 certificates.</p>
			
			<h2>Configuration</h2>
			<pre>
import (
    "crypto/tls"
    "crypto/x509"
    "os"
)

// Load CA certificate pool
caCert, _ := os.ReadFile("ca.crt")
caCertPool := x509.NewCertPool()
caCertPool.AppendCertsFromPEM(caCert)

// Configure TLS
tlsConfig := &tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  caCertPool,
}

// Create mTLS authentication provider
authProvider := security.MtlsAuthenticationProvider().
    ExtractUsername(security.MtlsUsernameFromDN).
    ExtractScopes(myScopeExtractor).
    Build()

securityFilter := security.Filter(false).
    Path("/api/**").
        Authentication(authProvider).
        Authorize().
    Build()

engine.AddFilter(securityFilter)

// Start server with TLS
engine.ListenWithTlsOptions(":8443", tlsConfig)
			</pre>

			<h2>Certificate Generation</h2>
			<pre>
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -key ca.key -out ca.crt -days 365

# Generate client private key
openssl genrsa -out client.key 4096

# Generate client certificate signing request
openssl req -new -key client.key -out client.csr

# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 365

# Create client PEM bundle
cat client.crt client.key > client.pem
			</pre>

			<h2>Username Extraction</h2>
			<p>Extract username from certificate Distinguished Name (DN):</p>
			<ul>
				<li><code>MtlsUsernameFromDN</code> - Full DN string</li>
				<li><code>MtlsUsernameFromCommonName</code> - CN field only</li>
				<li><code>MtlsUsernameFromEmailAddress</code> - Email from certificate</li>
			</ul>

			<h2>Testing with curl</h2>
			<pre>
# Make request with client certificate
curl --cert client.pem --cacert ca.crt https://localhost:8443/api/data
			</pre>

			<h2>Use Cases</h2>
			<ul>
				<li>Service-to-service authentication</li>
				<li>High-security environments</li>
				<li>IoT device authentication</li>
				<li>API authentication without tokens</li>
			</ul>

			<h2>Note</h2>
			<p>This example shows the configuration pattern. Actual mTLS requires:</p>
			<ol>
				<li>Server certificate and key</li>
				<li>Client certificates signed by trusted CA</li>
				<li>TLS configuration at server startup</li>
			</ol>
		`)
		return nil
	})

	fmt.Println("mTLS Authentication Example")
	fmt.Println("This demonstrates the configuration pattern for mTLS.")
	fmt.Println("See the source code for full configuration details.")
	fmt.Println()
	fmt.Println("Server starting on http://localhost:8080")
	fmt.Println("Press Ctrl+C to stop")

	if err := engine.Listen(":8080"); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

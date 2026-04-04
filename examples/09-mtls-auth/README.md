# Mutual TLS (mTLS) Authentication Example

Demonstrates the configuration pattern for mTLS authentication using client certificates.

## What is mTLS?

Mutual TLS requires both client and server to authenticate using X.509 certificates. Unlike standard TLS (where only the server is authenticated), mTLS verifies both parties.

## Configuration Pattern

```go
authProvider := security.MtlsAuthenticationProvider().
    ExtractUsername(security.MtlsUsernameFromCommonName).
    ExtractScopes(scopeExtractorFunc).
    Build()
```

## Certificate Setup

mTLS requires:
- **Server certificate** - Server's identity
- **CA certificate** - Trusted certificate authority  
- **Client certificates** - Each client's identity (signed by CA)

## Username Extraction

Choose how to extract username from certificate:

- `MtlsUsernameFromDN` - Full Distinguished Name
- `MtlsUsernameFromCommonName` - CN field only
- `MtlsUsernameFromEmailAddress` - Email address

## Use Cases

- **Service-to-service** - Microservices authentication
- **IoT devices** - Device authentication
- **High security** - Government, financial systems
- **API authentication** - Alternative to API keys/tokens

## Next Steps

- [10-authorization](../10-authorization/) - Authorization and RBAC
- [BEST_PRACTICES](../../docs/BEST_PRACTICES.md) - Security patterns

# IdentityHub

A .NET 10 starter for an OpenID Connect/OAuth 2.0 identity provider built on
Duende IdentityServer 8.0.9. It supports external sign-in through Microsoft,
Google, and AWS Cognito. AWS integration here means Cognito federation over
OIDC, not AWS IAM authentication.

Duende IdentityServer is commercial software. Review Duende's current license
terms and obtain the appropriate license before production use.

## Run locally

1. Install the .NET 10 SDK.
2. Create OAuth/OIDC applications with the desired providers and register these
   callback URLs:
   - Google: `https://localhost:5001/signin-google`
   - Microsoft: `https://localhost:5001/signin-microsoft`
   - AWS Cognito: `https://localhost:5001/signin-aws-cognito`
3. Set credentials in environment variables (do not commit secrets):

   ```powershell
   $env:Authentication__Google__ClientId = "..."
   $env:Authentication__Google__ClientSecret = "..."
   $env:Authentication__Microsoft__ClientId = "..."
   $env:Authentication__Microsoft__ClientSecret = "..."
   $env:Authentication__Microsoft__TenantId = "common"
   $env:Authentication__AwsCognito__Authority = "https://your-domain.auth.us-east-1.amazoncognito.com"
   $env:Authentication__AwsCognito__ClientId = "..."
   $env:Authentication__AwsCognito__ClientSecret = "..."
   ```

   Configure only the providers you need. For Cognito, use the User Pool OIDC
   issuer/authority URL shown in the pool's OIDC discovery document. Its app
   client may omit a secret if configured as a public PKCE client.
4. Run `dotnet run` from this directory. The development signing key is for
   local use only.
5. Browse to `https://localhost:5001/.well-known/openid-configuration`.

The login UI is at `/Account/Login`. In a real flow it is reached by a registered
client's authorization request. The in-memory `sample-web-client` registration
is only an example; replace its redirect URIs, scopes, and client settings for
your applications. In-memory clients and scopes do not persist across restarts.

## Production notes

- Configure `IdentityServer:SigningCertificate:Path` and
  `IdentityServer:SigningCertificate:Password` using deployment secrets. The
  app refuses to start outside Development without a signing certificate.
- Replace in-memory clients, scopes, and resources with persistent configuration
  and use a durable user/account-linking store.
- Set each provider's production redirect URI and verify its issuer, scopes,
  consent, account-linking, and logout behavior before deployment.
- Add operational protections appropriate to your deployment, including
  HTTPS, secure secret storage, key rotation, monitoring, and a supported
  Duende license.

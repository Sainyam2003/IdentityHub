using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
var isDevelopment = builder.Environment.IsDevelopment();

builder.Services.AddControllersWithViews();

var identityServerBuilder = builder.Services
    .AddIdentityServer(options => options.EmitStaticAudienceClaim = true)
    .AddInMemoryIdentityResources(
    [
        new IdentityResources.OpenId(),
        new IdentityResources.Profile(),
        new IdentityResources.Email()
    ])
    .AddInMemoryApiScopes(
    [
        new ApiScope("sample-api", "Sample API")
    ])
    .AddInMemoryApiResources(
    [
        new ApiResource("sample-api", "Sample API")
        {
            Scopes = { "sample-api" }
        }
    ])
    .AddInMemoryClients(
    [
        new Client
        {
            ClientId = "sample-web-client",
            ClientName = "Sample web client",
            AllowedGrantTypes = GrantTypes.Code,
            RequirePkce = true,
            RequireClientSecret = false,
            RedirectUris = { "https://localhost:5002/signin-oidc" },
            PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
            AllowedScopes =
            {
                IdentityServerConstants.StandardScopes.OpenId,
                IdentityServerConstants.StandardScopes.Profile,
                IdentityServerConstants.StandardScopes.Email,
                IdentityServerConstants.StandardScopes.OfflineAccess,
                "sample-api"
            },
            AllowOfflineAccess = true
        }
    ]);

if (isDevelopment)
{
    identityServerBuilder.AddDeveloperSigningCredential();
}
else
{
    var certificatePath = configuration["IdentityServer:SigningCertificate:Path"];
    if (string.IsNullOrWhiteSpace(certificatePath))
    {
        throw new InvalidOperationException(
            "IdentityServer:SigningCertificate:Path must be configured outside Development.");
    }

    var certificatePassword = configuration["IdentityServer:SigningCertificate:Password"];
    var signingCertificate = X509CertificateLoader.LoadPkcs12FromFile(
        certificatePath,
        certificatePassword);
    identityServerBuilder.AddSigningCredential(signingCertificate);
}

var authentication = builder.Services.AddAuthentication();
ConfigureGoogle(authentication, configuration);
ConfigureMicrosoft(authentication, configuration);
ConfigureAwsCognito(authentication, configuration);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
app.UseAuthorization();
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

static void ConfigureGoogle(
    AuthenticationBuilder authentication,
    IConfiguration configuration)
{
    var clientId = configuration["Authentication:Google:ClientId"];
    var clientSecret = configuration["Authentication:Google:ClientSecret"];
    EnsureCredentialsAreComplete("Google", clientId, clientSecret);

    if (string.IsNullOrWhiteSpace(clientId))
    {
        return;
    }

    authentication.AddGoogle("Google", options =>
    {
        options.ClientId = clientId;
        options.ClientSecret = clientSecret!;
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.SaveTokens = false;
    });
}

static void ConfigureMicrosoft(
    AuthenticationBuilder authentication,
    IConfiguration configuration)
{
    var clientId = configuration["Authentication:Microsoft:ClientId"];
    var clientSecret = configuration["Authentication:Microsoft:ClientSecret"];
    EnsureCredentialsAreComplete("Microsoft", clientId, clientSecret);

    if (string.IsNullOrWhiteSpace(clientId))
    {
        return;
    }

    var tenant = configuration["Authentication:Microsoft:TenantId"] ?? "common";
    authentication.AddOpenIdConnect("Microsoft", options =>
    {
        options.Authority = $"https://login.microsoftonline.com/{tenant}/v2.0";
        options.ClientId = clientId;
        options.ClientSecret = clientSecret!;
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.CallbackPath = "/signin-microsoft";
        options.ResponseType = "code";
        options.UsePkce = true;
        options.MapInboundClaims = false;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;
        options.Scope.Add("email");
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "roles"
        };
    });
}

static void ConfigureAwsCognito(
    AuthenticationBuilder authentication,
    IConfiguration configuration)
{
    var authority = configuration["Authentication:AwsCognito:Authority"];
    var clientId = configuration["Authentication:AwsCognito:ClientId"];

    if (string.IsNullOrWhiteSpace(authority) != string.IsNullOrWhiteSpace(clientId))
    {
        throw new InvalidOperationException(
            "Configure both Authentication:AwsCognito:Authority and ClientId to enable AWS Cognito.");
    }

    if (string.IsNullOrWhiteSpace(authority))
    {
        return;
    }

    authentication.AddOpenIdConnect("AwsCognito", options =>
    {
        options.Authority = authority;
        options.ClientId = clientId!;
        options.ClientSecret = configuration["Authentication:AwsCognito:ClientSecret"];
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.CallbackPath = "/signin-aws-cognito";
        options.ResponseType = "code";
        options.UsePkce = true;
        options.MapInboundClaims = false;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "cognito:groups"
        };
    });
}

static void EnsureCredentialsAreComplete(
    string provider,
    string? clientId,
    string? clientSecret)
{
    if (string.IsNullOrWhiteSpace(clientId) != string.IsNullOrWhiteSpace(clientSecret))
    {
        throw new InvalidOperationException(
            $"Configure both Authentication:{provider}:ClientId and ClientSecret to enable {provider}.");
    }
}

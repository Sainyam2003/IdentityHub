using System.Security.Claims;
using Duende.IdentityServer;
using IdentityHub.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace IdentityHub.Controllers;

public sealed class AccountController(
    IAuthenticationSchemeProvider schemeProvider,
    ILogger<AccountController> logger) : Controller
{
    private static readonly HashSet<string> ExternalSchemeNames =
        ["Google", "Microsoft", "AwsCognito"];

    [HttpGet]
    public async Task<IActionResult> Login(string? returnUrl, string? error)
    {
        var schemes = await schemeProvider.GetAllSchemesAsync();
        var providers = schemes
            .Where(scheme => ExternalSchemeNames.Contains(scheme.Name))
            .Select(scheme => new LoginProvider(
                scheme.Name,
                scheme.DisplayName ?? scheme.Name))
            .ToArray();

        return View(new LoginViewModel(
            returnUrl,
            error == "external" ? "Sign-in with the selected provider failed. Please try again." : null,
            providers));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ExternalLogin(string provider, string? returnUrl)
    {
        if (!ExternalSchemeNames.Contains(provider))
        {
            return BadRequest("Unknown external identity provider.");
        }

        var schemes = await schemeProvider.GetAllSchemesAsync();
        if (!schemes.Any(scheme => scheme.Name == provider))
        {
            return BadRequest("The requested identity provider is not configured.");
        }

        var safeReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl : Url.Content("~/");
        var callbackUrl = Url.Action(
            nameof(ExternalCallback),
            "Account",
            new { provider, returnUrl = safeReturnUrl });

        return Challenge(
            new AuthenticationProperties { RedirectUri = callbackUrl },
            provider);
    }

    [HttpGet]
    public async Task<IActionResult> ExternalCallback(string provider, string? returnUrl)
    {
        if (!ExternalSchemeNames.Contains(provider))
        {
            return BadRequest("Unknown external identity provider.");
        }

        var authentication = await HttpContext.AuthenticateAsync(
            IdentityServerConstants.ExternalCookieAuthenticationScheme);

        if (!authentication.Succeeded || authentication.Principal is null)
        {
            logger.LogWarning("External sign-in failed for provider {Provider}.", provider);
            await HttpContext.SignOutAsync(
                IdentityServerConstants.ExternalCookieAuthenticationScheme);
            return RedirectToAction(nameof(Login), new { returnUrl, error = "external" });
        }

        var providerSubject = authentication.Principal.FindFirst("sub")?.Value
            ?? authentication.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrWhiteSpace(providerSubject))
        {
            logger.LogWarning(
                "External provider {Provider} returned no stable subject identifier.",
                provider);
            await HttpContext.SignOutAsync(
                IdentityServerConstants.ExternalCookieAuthenticationScheme);
            return RedirectToAction(nameof(Login), new { returnUrl, error = "external" });
        }

        var claims = CreateIdentityClaims(authentication.Principal, provider, providerSubject);
        await HttpContext.SignOutAsync(
            IdentityServerConstants.ExternalCookieAuthenticationScheme);

        var identity = new ClaimsIdentity(
            claims,
            IdentityServerConstants.DefaultCookieAuthenticationScheme,
            "name",
            "role");
        await HttpContext.SignInAsync(
            IdentityServerConstants.DefaultCookieAuthenticationScheme,
            new ClaimsPrincipal(identity));

        return Url.IsLocalUrl(returnUrl)
            ? LocalRedirect(returnUrl!)
            : RedirectToAction("Index", "Home");
    }

    private static List<Claim> CreateIdentityClaims(
        ClaimsPrincipal externalPrincipal,
        string provider,
        string providerSubject)
    {
        var claims = new List<Claim>
        {
            new("sub", $"{provider}:{providerSubject}"),
            new("idp", provider)
        };

        var name = externalPrincipal.FindFirst("name")?.Value
            ?? externalPrincipal.FindFirst(ClaimTypes.Name)?.Value
            ?? externalPrincipal.Identity?.Name
            ?? providerSubject;
        claims.Add(new Claim("name", name));

        var email = externalPrincipal.FindFirst("email")?.Value
            ?? externalPrincipal.FindFirst(ClaimTypes.Email)?.Value;
        if (!string.IsNullOrWhiteSpace(email))
        {
            claims.Add(new Claim("email", email));

            var emailVerified = externalPrincipal.FindFirst("email_verified")?.Value;
            if (bool.TryParse(emailVerified, out var isVerified) && isVerified)
            {
                claims.Add(new Claim("email_verified", "true"));
            }
        }

        AddOptionalClaim(externalPrincipal, claims, "given_name", ClaimTypes.GivenName);
        AddOptionalClaim(externalPrincipal, claims, "family_name", ClaimTypes.Surname);
        AddOptionalClaim(externalPrincipal, claims, "preferred_username");

        return claims;
    }

    private static void AddOptionalClaim(
        ClaimsPrincipal principal,
        ICollection<Claim> destination,
        string claimType,
        string? fallbackClaimType = null)
    {
        var value = principal.FindFirst(claimType)?.Value
            ?? (fallbackClaimType is null ? null : principal.FindFirst(fallbackClaimType)?.Value);

        if (!string.IsNullOrWhiteSpace(value))
        {
            destination.Add(new Claim(claimType, value));
        }
    }
}

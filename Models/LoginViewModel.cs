namespace IdentityHub.Models;

public sealed record LoginProvider(string Scheme, string DisplayName);

public sealed record LoginViewModel(
    string? ReturnUrl,
    string? Error,
    IReadOnlyList<LoginProvider> Providers);

using System.Security.Claims;
using System.Text.Encodings.Web;
using Api.Authentication.Scheme.Configurations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Api.Authentication.Scheme.Handlers;

public class ApiKeyAuthenticationHandler(
    IOptionsMonitor<ApiKeyConfiguration> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<ApiKeyConfiguration>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.ApiKeyHeaderName, out var apiKey))
            return Task.FromResult(AuthenticateResult.Fail("Missing API Key"));

        if (apiKey != Options.ApiKeyHeaderValue)
            return Task.FromResult(AuthenticateResult.Fail("Invalid API Key"));
        
        var claims = new[] { new Claim(ClaimTypes.Name, "AuthenticatedUser") };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
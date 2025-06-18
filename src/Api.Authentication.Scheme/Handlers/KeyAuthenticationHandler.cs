using System.Security.Claims;
using System.Text.Encodings.Web;
using Api.Authentication.Scheme.Configurations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Api.Authentication.Scheme.Handlers;

public class KeyAuthenticationHandler(
    IOptionsMonitor<KeyConfiguration> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IKeyAuthenticationService authenticationService)
    : AuthenticationHandler<KeyConfiguration>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Options.HeaderName, out var headerValue))
            return AuthenticateResult.Fail("Missing API Key");

        if (!await authenticationService.Authenticate(headerValue))
            return AuthenticateResult.Fail("Invalid API Key");
        
        var claims = new[] { new Claim(ClaimTypes.Name, "AuthenticatedUser") };
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}
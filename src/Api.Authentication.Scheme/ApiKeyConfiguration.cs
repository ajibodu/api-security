using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication.Scheme;

public class ApiKeyConfiguration : AuthenticationSchemeOptions
{
    public string ApiKeyHeaderValue { get; set; }
    public string ApiKeyHeaderName { get; set; }
}
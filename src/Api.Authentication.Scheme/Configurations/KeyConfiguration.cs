using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication.Scheme.Configurations;

public interface IKeyConfiguration
{
    public string HeaderName { get; set; }
}

public class KeyConfiguration : AuthenticationSchemeOptions, IKeyConfiguration
{
    public string HeaderName { get; set; } = string.Empty;
}

public record SimpleKeyConfiguration(string HeaderName, string HeaderValue);
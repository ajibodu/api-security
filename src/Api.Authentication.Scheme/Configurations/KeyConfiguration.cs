using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication.Scheme.Configurations;

public interface IKeyConfiguration
{
    public string HeaderName { get; set; }
}

public class KeyConfiguration : AuthenticationSchemeOptions, IKeyConfiguration
{
    public string HeaderName { get; set; }
}

public class SimpleKeyConfiguration
{
    public string HeaderName { get; set; }
    public string HeaderValue { get; set; }
}
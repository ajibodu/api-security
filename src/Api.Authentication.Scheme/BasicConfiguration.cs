using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication.Scheme;

public interface IBasicConfiguration
{
    public string UserName { get; set; }
    public string Password { get; set; }
}
public class BasicConfiguration : AuthenticationSchemeOptions, IBasicConfiguration
{
    public string UserName { get; set; }
    public string Password { get; set; }
}
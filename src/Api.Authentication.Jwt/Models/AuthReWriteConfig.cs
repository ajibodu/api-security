using Microsoft.AspNetCore.Http;

namespace Api.Authentication.Jwt.Models;

public class AuthReWriteConfig
{
    public required IEnumerable<PathString> PathStrings { get; set; }
    public Mapping? Token { get; set; }
    public Dictionary<string, Mapping> Headers { get; set; } = new();
}

public class Mapping
{
    public Source From { get; set; }
    public required string Key { get; set; }
}

public enum Source
{
    Query,
    Header,
    Cookie
}
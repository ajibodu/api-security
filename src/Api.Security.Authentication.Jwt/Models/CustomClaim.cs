namespace Api.Security.Authentication.Jwt.Models;

public record CustomClaim(string Type, string Value, string ValueType = CustomClaimValueTypes.String, bool IsUniqueId = false)
{
    public string Type { get; set; } = Type;
    public string Value { get; set; } = Value;
    public string ValueType { get; set; } = ValueType;
    public bool IsUniqueId { get; set; } = IsUniqueId;
}
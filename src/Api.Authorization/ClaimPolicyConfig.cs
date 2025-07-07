namespace Api.Authorization;

public class ClaimPolicyConfig
{
    public string ClaimType { get; set; } = string.Empty;
    public string[] RequiredValues { get; set; } = [];
}
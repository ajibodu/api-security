using System.Security.Claims;

namespace Api.Security.Authentication.Jwt.Models;

/// <summary>
/// Combination of ClaimValueTypes and JsonClaimValueTypes
/// Copied from System.Security.Claims.ClaimValueTypes
/// Copied from System.IdentityModel.Tokens.Jwt.JsonClaimValueTypes
/// </summary>
public class CustomClaimValueTypes
{
    public const string Base64Binary = "http://www.w3.org/2001/XMLSchema#base64Binary";
    /// <summary>A URI that represents the <see langword="base64Octet" /> XML data type.</summary>
    public const string Base64Octet = "http://www.w3.org/2001/XMLSchema#base64Octet";
    /// <summary>A URI that represents the <see langword="boolean" /> XML data type.</summary>
    public const string Boolean = "http://www.w3.org/2001/XMLSchema#boolean";
    /// <summary>A URI that represents the <see langword="date" /> XML data type.</summary>
    public const string Date = "http://www.w3.org/2001/XMLSchema#date";
    /// <summary>A URI that represents the <see langword="dateTime" /> XML data type.</summary>
    public const string DateTime = "http://www.w3.org/2001/XMLSchema#dateTime";
    /// <summary>A URI that represents the <see langword="double" /> XML data type.</summary>
    public const string Double = "http://www.w3.org/2001/XMLSchema#double";
    /// <summary>A URI that represents the <see langword="fqbn" /> XML data type.</summary>
    public const string Fqbn = "http://www.w3.org/2001/XMLSchema#fqbn";
    /// <summary>A URI that represents the <see langword="hexBinary" /> XML data type.</summary>
    public const string HexBinary = "http://www.w3.org/2001/XMLSchema#hexBinary";
    /// <summary>A URI that represents the <see langword="integer" /> XML data type.</summary>
    public const string Integer = "http://www.w3.org/2001/XMLSchema#integer";
    /// <summary>A URI that represents the <see langword="integer32" /> XML data type.</summary>
    public const string Integer32 = "http://www.w3.org/2001/XMLSchema#integer32";
    /// <summary>A URI that represents the <see langword="integer64" /> XML data type.</summary>
    public const string Integer64 = "http://www.w3.org/2001/XMLSchema#integer64";
    /// <summary>A URI that represents the <see langword="sid" /> XML data type.</summary>
    public const string Sid = "http://www.w3.org/2001/XMLSchema#sid";
    /// <summary>A URI that represents the <see langword="string" /> XML data type.</summary>
    public const string String = "http://www.w3.org/2001/XMLSchema#string";
    /// <summary>A URI that represents the <see langword="time" /> XML data type.</summary>
    public const string Time = "http://www.w3.org/2001/XMLSchema#time";
    /// <summary>A URI that represents the <see langword="uinteger32" /> XML data type.</summary>
    public const string UInteger32 = "http://www.w3.org/2001/XMLSchema#uinteger32";
    /// <summary>A URI that represents the <see langword="uinteger64" /> XML data type.</summary>
    public const string UInteger64 = "http://www.w3.org/2001/XMLSchema#uinteger64";
    /// <summary>A URI that represents the <see langword="dns" /> SOAP data type.</summary>
    public const string DnsName = "http://schemas.xmlsoap.org/claims/dns";
    /// <summary>A URI that represents the <see langword="emailaddress" /> SOAP data type.</summary>
    public const string Email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
    /// <summary>A URI that represents the <see langword="rsa" /> SOAP data type.</summary>
    public const string Rsa = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/rsa";
    /// <summary>A URI that represents the <see langword="UPN" /> SOAP data type.</summary>
    public const string UpnName = "http://schemas.xmlsoap.org/claims/UPN";
    /// <summary>A URI that represents the <see langword="DSAKeyValue" /> XML Signature data type.</summary>
    public const string DsaKeyValue = "http://www.w3.org/2000/09/xmldsig#DSAKeyValue";
    /// <summary>A URI that represents the <see langword="KeyInfo" /> XML Signature data type.</summary>
    public const string KeyInfo = "http://www.w3.org/2000/09/xmldsig#KeyInfo";
    /// <summary>A URI that represents the <see langword="RSAKeyValue" /> XML Signature data type.</summary>
    public const string RsaKeyValue = "http://www.w3.org/2000/09/xmldsig#RSAKeyValue";
    /// <summary>A URI that represents the <see langword="daytimeDuration" /> XQuery data type.</summary>
    public const string DaytimeDuration = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#dayTimeDuration";
    /// <summary>A URI that represents the <see langword="yearMonthDuration" /> XQuery data type.</summary>
    public const string YearMonthDuration = "http://www.w3.org/TR/2002/WD-xquery-operators-20020816#yearMonthDuration";
    /// <summary>A URI that represents the <see langword="rfc822Name" /> XACML 1.0 data type.</summary>
    public const string Rfc822Name = "urn:oasis:names:tc:xacml:1.0:data-type:rfc822Name";
    /// <summary>A URI that represents the <see langword="x500Name" /> XACML 1.0 data type.</summary>
    public const string X500Name = "urn:oasis:names:tc:xacml:1.0:data-type:x500Name";
    
    
    
    /// <summary>
    /// A value that indicates the <see cref="Claim.Value"/> is a Json object.
    /// </summary>
    /// <remarks>When creating a <see cref="Claim"/> from Json if the value was not a simple type {String, Null, True, False, Number}
    /// then <see cref="Claim.Value"/> will contain the Json value. If the Json was a JsonObject, the <see cref="Claim.ValueType"/> will be set to "JSON".</remarks>
    public const string Json = "JSON";

    /// <summary>
    /// A value that indicates the <see cref="Claim.Value"/> is a Json object.
    /// </summary>
    /// <remarks>When creating a <see cref="Claim"/> from Json if the value was not a simple type {String, Null, True, False, Number}
    /// then <see cref="Claim.Value"/> will contain the Json value. If the Json was a JsonArray, the <see cref="Claim.ValueType"/> will be set to "JSON_ARRAY".</remarks>
    public const string JsonArray = "JSON_ARRAY";

    /// <summary>
    /// A value that indicates the <see cref="Claim.Value"/> is Json null.
    /// </summary>
    /// <remarks>When creating a <see cref="Claim"/> the <see cref="Claim.Value"/> cannot be null. If the Json value was null, then the <see cref="Claim.Value"/>
    /// will be set to <see cref="string.Empty"/> and the <see cref="Claim.ValueType"/> will be set to "JSON_NULL".</remarks>
    public const string JsonNull = "JSON_NULL";
}
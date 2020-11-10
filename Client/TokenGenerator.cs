using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Client
{
    /// <summary>
    /// Generates a JWT suitable for use when accessing the PayPattern.io API.
    /// </summary>
    /// <remarks>
    /// First generate a RsaJwk and share the PK json with PayPattern
    /// </remarks>
    public class TokenGenerator
    {
        private readonly RsaJwk _key;
        private readonly string _issuer;
        private readonly string _audience;

        private readonly JwtSecurityTokenHandler _handler = new JwtSecurityTokenHandler();
        
        public TokenGenerator(RsaJwk key, string issuer, string audience)
        {
            _key = key;
            _issuer = issuer;
            _audience = audience;
        }

        public string Generate(string userId, TimeSpan? duration = null)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, userId)
                }),
                Expires = DateTime.UtcNow.Add(duration ?? TimeSpan.FromHours(1)),
                Issuer = _issuer,
                Audience = _audience,
                SigningCredentials = _key.SigningCredentials,
            };

            var token = _handler.CreateToken(descriptor);
            return _handler.WriteToken(token);
        }
    }
}
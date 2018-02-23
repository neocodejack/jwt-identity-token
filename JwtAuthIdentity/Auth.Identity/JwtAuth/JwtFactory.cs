using Auth.Identity.Helpers;
using Auth.Identity.Models;
using Microsoft.Extensions.Options;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace Auth.Identity.Jwt
{
    public class JwtFactory : IJwtFactory
    {
        private JwtIssuerOptions _issuerOptions;

        public JwtFactory(IOptions<JwtIssuerOptions> issuerOptions)
        {
            _issuerOptions = issuerOptions.Value;
            ExceptionIfInvalidOptions(_issuerOptions);
        }

        private static void ExceptionIfInvalidOptions(JwtIssuerOptions issuerOptions)
        {
            if (issuerOptions == null) throw new ArgumentNullException(nameof(issuerOptions));

            if (issuerOptions.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (issuerOptions.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (issuerOptions.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }

        //Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC)
        private static long ConvertToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() -
                               new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                              .TotalSeconds);

        public ClaimsIdentity CreateClaimsIdentity(string userName, string id)
        {
            return new ClaimsIdentity(new GenericIdentity(userName, "Token"), new[]
            {
                new Claim(Constants.Strings.JwtClaimIdentifiers.Id, id),
                new Claim(Constants.Strings.JwtClaimIdentifiers.Rol, Constants.Strings.JwtClaims.ApiAccess)
            });
        }

        public async Task<string> CreateEncodedToken(string userName, ClaimsIdentity identity)
        {
            var claims = new[]
            {
                 new Claim(JwtRegisteredClaimNames.Sub, userName),
                 new Claim(JwtRegisteredClaimNames.Jti, await _issuerOptions.JtiGenerator()),
                 new Claim(JwtRegisteredClaimNames.Iat, ConvertToUnixEpochDate(_issuerOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                 identity.FindFirst(Constants.Strings.JwtClaimIdentifiers.Rol),
                 identity.FindFirst(Constants.Strings.JwtClaimIdentifiers.Id)
             };

            // Create the JWT security token and encode it.
            var jwt = new JwtSecurityToken(
                issuer: _issuerOptions.Issuer,
                audience: _issuerOptions.Audience,
                claims: claims,
                notBefore: _issuerOptions.NotBefore,
                expires: _issuerOptions.Expiration,
                signingCredentials: _issuerOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return encodedJwt;
        }
    }
}

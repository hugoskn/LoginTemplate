using Microsoft.IdentityModel.Tokens;
using LoginJwt.Tools.Extensions;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginJwt.Authorization.Tokenizers
{
    public class JwtTokenizer
    {
        public static string GenerateJwtToken(string userId, string userEmail)
        {
            if (userId.IsAnyNullOrWhiteSpace(userEmail))
            {
                return null;
            }

            var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345"));
            var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);

            var tokeOptions = new JwtSecurityToken(
                issuer: "https://www.LoginJwt.com",
                audience: "https://www.LoginJwt.com",
                claims: GenerateClaims(userId, userEmail),
                expires: DateTime.Now.AddDays(10),
                signingCredentials: signinCredentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
            return tokenString;
        }

        private static IEnumerable<Claim> GenerateClaims(string userId, string email)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.Name, email),
                new Claim(ClaimTypes.Email, email),
                new Claim(ClaimTypes.Sid, userId),
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.PrimarySid, userId)
            };
        }

    }
}

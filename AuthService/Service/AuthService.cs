using AuthService.Interface;
using AuthService.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthService.Service
{
    public class AuthService : IAuthService
    {
        private readonly IConfiguration _config;
        // This simulates a database table of refresh tokens
        private static readonly List<RefreshToken> _refreshTokens = new();

        public AuthService(IConfiguration config)
        {
            _config = config;
        }

        public TokenResponse Authenticate(string username, string password)
        {
            if (username != "Admin" || password != "Password@123")
            {
                return null;
            }
            var accessToken = GenerateJwtToken(username);
            var refreshToken = GenerateRefreshToken();
            _refreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Username = username,
                ExpiryTime = DateTime.UtcNow.AddHours(Convert.ToInt32(_config["JwtSettings:refreshExpiryHour"]))
            });

            return new TokenResponse { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        public TokenResponse Refresh(string refreshToken)
        {
            var exisitingRefreshToken = _refreshTokens.FirstOrDefault(x => x.Token == refreshToken);
            if (exisitingRefreshToken == null)
                return null;

            // Check expiry
            if (exisitingRefreshToken.ExpiryTime < DateTime.UtcNow)
            {
                // Remove expired token
                _refreshTokens.Remove(exisitingRefreshToken);
                return null;
            }

            var username = exisitingRefreshToken.Username;

            // Optionally rotate refresh tokens (invalidate old one)
            var accesToken = GenerateJwtToken(username);
            var newRefreshToken = GenerateRefreshToken();

            _refreshTokens.Remove(exisitingRefreshToken);
            _refreshTokens.Add(new RefreshToken
            {
                Token = newRefreshToken,
                Username = username,
                ExpiryTime = DateTime.UtcNow.AddHours(Convert.ToInt32(_config["JwtSettings:refreshExpiryHour"]))
            });

            return new TokenResponse
            {
                AccessToken = accesToken,
                RefreshToken = newRefreshToken
            };
        }

        private string GenerateJwtToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securekey = Encoding.UTF8.GetBytes(_config["JwtSettings:SecretKey"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name,_config["JwtSettings:Audience"]),
                    new Claim(ClaimTypes.Role,"Admin")
                }),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToInt32(_config["JwtSettings:ExpiryMinutes"])),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(securekey), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _config["JwtSettings:Issuer"],
                Audience = _config["JwtSettings:Audience"]
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private static string GenerateRefreshToken()
        {
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
    }
}

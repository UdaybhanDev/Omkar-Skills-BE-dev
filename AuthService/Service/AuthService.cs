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
        private static readonly List<UserRecord> _users = new();
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

        public TokenResponse Register(RegisterDTO registerDTO)
        {
            if (registerDTO == null)
                return null;

            if (string.IsNullOrWhiteSpace(registerDTO.UserName) ||
                string.IsNullOrWhiteSpace(registerDTO.Password) ||
                string.IsNullOrWhiteSpace(registerDTO.Email))
            {
                return null;
            }

            // Check uniqueness
            if (_users.Any(u => u.UserName.Equals(registerDTO.UserName, StringComparison.OrdinalIgnoreCase)
                             || u.Email.Equals(registerDTO.Email, StringComparison.OrdinalIgnoreCase)))
            {
                return null;
            }

            var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var hash = HashPassword(registerDTO.Password, salt);

            var user = new UserRecord
            {
                UserName = registerDTO.UserName,
                Email = registerDTO.Email,
                Salt = salt,
                PasswordHash = hash
            };

            _users.Add(user);

            // Issue tokens for the new user
            var accessToken = GenerateJwtToken(user.UserName);
            var refreshToken = GenerateRefreshToken();
            _refreshTokens.Add(new RefreshToken
            {
                Token = refreshToken,
                Username = user.UserName,
                ExpiryTime = DateTime.UtcNow.AddHours(Convert.ToInt32(_config["JwtSettings:refreshExpiryHour"]))
            });

            return new TokenResponse { AccessToken = accessToken, RefreshToken = refreshToken };
        }

        // New: return public user list (no secrets)
        public IEnumerable<UserDto> GetAllUsers()
        {
            return _users.Select(u => new UserDto
            {
                UserName = u.UserName,
                Email = u.Email
            }).ToList();
        }

        private static string HashPassword(string password, string saltBase64)
        {
            var salt = Convert.FromBase64String(saltBase64);
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(32);
            return Convert.ToBase64String(hash);
        }

        private static string HashPasswordStatic(string password, string saltBase64)
        {
            // helper for static constructor
            return HashPassword(password, saltBase64);
        }

        private static bool VerifyPassword(string password, string saltBase64, string expectedHashBase64)
        {
            var computed = HashPassword(password, saltBase64);
            return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(computed), Convert.FromBase64String(expectedHashBase64));
        }
    }
}

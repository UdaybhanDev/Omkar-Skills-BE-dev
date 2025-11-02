using AuthService.Model;
using AuthService.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    public class LoginController : Controller
    {
        private readonly IAuthService _authService;
        public LoginController(IAuthService authService)
        {
            _authService = authService;
        }
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost("login")]
        public IActionResult Login(LoginRequest loginRequest)
        {
            var token = _authService.Authenticate(loginRequest.UserName, loginRequest.Password);
            if (token == null)
            {
                return Unauthorized(new { message = "Invalid credentials" });
            }
            return Ok(new { token });
        }

        [HttpPost("refreshToken")]
        public IActionResult Refresh([FromBody] string refreshToken)
        {
            var tokens = _authService.Refresh(refreshToken);

            if (tokens == null)
                return Unauthorized(new { message = "Invalid refresh token" });

            return Ok(tokens);
        }

        [Authorize]
        [HttpPost("ValidateToken")]
        public IActionResult ValidateToken(LoginRequest loginRequest)
        {
            var token = _authService.Authenticate(loginRequest.UserName, loginRequest.Password);
            if (token == null)
            {
                return Unauthorized(new { message = "Invalid credentials" });
            }
            return Ok(new { token });
        }
    }
}

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
        // GET api/login/GetAllEmp
        //[Authorize]
        [HttpGet("GetAllEmp")]
        public IActionResult GetAllEmp()
        {
            var users = _authService.GetAllUsers();
            return Ok(users);
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
        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterDTO registerDTO)
        {
            if (registerDTO == null)
                return BadRequest(new { message = "Request body is required." });

            if (string.IsNullOrWhiteSpace(registerDTO.Email)
                || string.IsNullOrWhiteSpace(registerDTO.UserName)
                || string.IsNullOrWhiteSpace(registerDTO.Password))
            {
                return BadRequest(new { message = "Email, UserName and Password are required." });
            }

            // Delegate registration to the service. Service returns tokens on success or null on failure.
            var tokens = _authService.Register(registerDTO);

            if (tokens == null)
            {
                // Prefer more specific errors from the service in a real implementation.
                return BadRequest(new { message = "Registration failed." });
            }

            return Ok(tokens);
        }
    }
}

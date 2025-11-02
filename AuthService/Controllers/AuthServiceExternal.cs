using AuthService.Interface;
using AuthService.Model;

namespace AuthService.Controllers
{
    public class AuthServiceExternal : IAuthService
    {
        public TokenResponse Authenticate(string username, string password)
        {
            throw new NotImplementedException();
        }

        public TokenResponse Refresh(string refreshToken)
        {
            throw new NotImplementedException();
        }
    }
}

using AuthService.Model;

namespace AuthService.Interface
{
    public interface IAuthService
    {
        TokenResponse Authenticate(string username, string password);
        TokenResponse Refresh(string refreshToken);
        TokenResponse Register(RegisterDTO registerDTO);
        IEnumerable<UserDto> GetAllUsers();
    }
}

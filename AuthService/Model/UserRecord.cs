namespace AuthService.Model
{
    // In-memory user store for demo purposes
    public class UserRecord
    {
        public string UserName { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public string Salt { get; set; } = null!;
    }
}

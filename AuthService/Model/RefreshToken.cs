namespace AuthService.Model
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public DateTime ExpiryTime { get; set; }
    }
}

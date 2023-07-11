namespace Csharpauth.Models
{
    public class TwoFactorAuthentication
    {
        //used to login
        public string Code { get; set; } = null!;

        //used to register / signup
        public string Token { get; set; } = null!;
        public string QRCodeUrl { get; set; } = null!;
    }
}
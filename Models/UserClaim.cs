namespace Csharpauth.Models
{
    public class UserClaim
    {
        public UserClaim()
        {
            Claims = new List<UserClaims>();
        }
        public string UserId { get; set; } = null!;
        public List<UserClaims> Claims { get; set; }

        public class UserClaims
        {
        public string ClaimType { get; set; } = null!;
        public bool IsSelected { get; set; }
        }
    }
}
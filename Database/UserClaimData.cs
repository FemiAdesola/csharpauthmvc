using System.Security.Claims;

namespace Csharpauth.Database
{
    public static class UserClaimData
    {
        public static List<Claim> claimsList = new List<Claim>()
        {
            new Claim("Create","Create"),
            new Claim("Edit","Edit"),
            new Claim("Delete","Delete")
        };
    }
}
using Microsoft.AspNetCore.Identity;

namespace Csharpauth.Models
{
    public class AppUser: IdentityUser
    {
        public string Name { get; set; } = null!;
    }
}
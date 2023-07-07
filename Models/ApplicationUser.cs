using Microsoft.AspNetCore.Identity;

namespace Csharpauth.Models
{
    internal class ApplicationUser : IdentityUser
    {
        public string UserName { get; set; }
        public string Email { get; set; }
        public string Name { get; set; }
    }
}
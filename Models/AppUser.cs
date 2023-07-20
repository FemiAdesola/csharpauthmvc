using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Csharpauth.Models
{
    public class AppUser: IdentityUser
    {
        public string Name { get; set; } = null!;

        // public string UserName { get; set; } 
        // public string Email { get; set; }

        [NotMapped]
        public string RoleId { get; set; }
        [NotMapped]
        public string Role{ get; set; }
    }
}
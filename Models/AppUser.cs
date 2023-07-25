using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Csharpauth.Models
{
    public class AppUser: IdentityUser
    {
        public string Name { get; set; } = null!;

        // public string UserName { get; set; } 
        // public string Email { get; set; }
        public DateTime DateCreated { get; set; }

        [NotMapped]
        public string? RoleId { get; set; }
        [NotMapped]
        public string? Role { get; set; }
        
        [NotMapped]
        public IEnumerable<SelectListItem>? RoleList { get; set; }
    }
}
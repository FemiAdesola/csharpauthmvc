using System.ComponentModel.DataAnnotations;

namespace Csharpauth.Models
{
    public class Login
    {
        [EmailAddress]
        public string Email { get; set; } = null!;

        [DataType(DataType.Password)]
        public string Password { get; set; }  = null!;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
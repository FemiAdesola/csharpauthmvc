using System.ComponentModel.DataAnnotations;

namespace Csharpauth.Models
{
    public class Register
    {
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = null!;

        
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = null!;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = null!;

        public string Name { get; set; } = null!;

    }
}
using System.ComponentModel.DataAnnotations;

namespace Csharpauth.Models
{
    public class ForgetPassword
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;
    }
}
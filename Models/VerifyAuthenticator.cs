using System.ComponentModel.DataAnnotations;

namespace Csharpauth.Models
{
    public class VerifyAuthenticator
    {
        [Required]
        public string Code { get; set; } = null!;
        public string ReturnUrl { get; set; }= null!;
        
        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
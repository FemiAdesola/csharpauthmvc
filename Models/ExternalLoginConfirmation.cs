using System.ComponentModel.DataAnnotations;

namespace Csharpauth.Models
{
    public class ExternalLoginConfirmation
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;

        public string Name { get; set; } = null!;
    }
}
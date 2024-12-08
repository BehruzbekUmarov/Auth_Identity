using System.ComponentModel.DataAnnotations;

namespace Auth_Identity.Api.Models.Authentication.SignUp;

public class RegiterUser
{
    [Required(ErrorMessage = "Username is required")]
    public string? Username { get; set; }
    [Required(ErrorMessage = "Email is required")]
    public string? Email { get; set; }
    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}

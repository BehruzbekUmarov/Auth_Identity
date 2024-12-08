using System.ComponentModel.DataAnnotations;

namespace Auth_Identity.Api.Models.Authentication.Login;

public class LoginModel
{
    [Required(ErrorMessage = "Username is required")]
    public string? Username { get; set; }

    [Required(ErrorMessage = "Password is required")]
    public string? Password { get; set; }
}

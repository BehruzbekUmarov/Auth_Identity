using System.ComponentModel.DataAnnotations;

namespace Auth_Identity.Service.Models.Authentication.SignUp;

public class ResetPassword
{
    public string Password { get; set; } = null!;
    [Compare("Password", ErrorMessage = "The Password and Confirmation password don't match")]
    public string ConfirmPassword { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Token { get; set; } = null!;
}

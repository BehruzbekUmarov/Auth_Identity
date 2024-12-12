using Auth_Identity.Data.Models;
using Microsoft.AspNetCore.Identity;

namespace Auth_Identity.Service.Models.Authentication.User;

public class LoginOtpResponse
{
    public string Token { get; set; } = null!;
    public bool IsTwoFactorEnable { get; set; }
    public ApplicationUser User { get; set; } = null!;
}

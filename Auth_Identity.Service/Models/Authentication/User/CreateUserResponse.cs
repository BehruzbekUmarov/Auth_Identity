using Auth_Identity.Data.Models;
using Microsoft.AspNetCore.Identity;

namespace Auth_Identity.Service.Models.Authentication.User;

public class CreateUserResponse
{
    public string Token { get; set; }
    public ApplicationUser User { get; set; }
}

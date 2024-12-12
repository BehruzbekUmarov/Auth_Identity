using Auth_Identity.Data.Models;
using Auth_Identity.Service.Models;
using Auth_Identity.Service.Models.Authentication.Login;
using Auth_Identity.Service.Models.Authentication.SignUp;
using Auth_Identity.Service.Models.Authentication.User;
using Microsoft.AspNetCore.Identity;

namespace Auth_Identity.Service.Services;

public interface IUserManagement
{
    Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegiterUser registerUser);
    Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);
    Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);
    Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user);
    Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);
}

using Auth_Identity.Service.Models;
using Auth_Identity.Service.Models.Authentication.SignUp;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Data;
using System;
using Microsoft.AspNetCore.Identity;
using Auth_Identity.Service.Models.Authentication.User;
using Auth_Identity.Service.Models.Authentication.Login;
using Microsoft.AspNetCore.Http;
using Auth_Identity.Data.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;

namespace Auth_Identity.Service.Services;

public class UserManagement : IUserManagement
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public UserManagement(
        RoleManager<IdentityRole> roleManager,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IConfiguration configuration)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }

    public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
    {
        var assignedRole = new List<string>();
        foreach(var role in roles)
        {
            if(await _roleManager.RoleExistsAsync(role))
            {
                if(await _roleManager.RoleExistsAsync(role))
                {
                    await _userManager.AddToRoleAsync(user, role);
                    assignedRole.Add(role);
                }
            }
        }

        return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Role has been assigned", Response = assignedRole};
    }

    public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegiterUser registerUser)
    {
        // Check user exist
        var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
        if (userExist != null)
        {
            return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exist!" };
        }
        // Add the user in the database
        ApplicationUser user = new()
        {
            Email = registerUser.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = registerUser.Username,
            TwoFactorEnabled = true
        };

        var result = await _userManager.CreateAsync(user, registerUser.Password);
        if (result.Succeeded)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            return new ApiResponse<CreateUserResponse> {Response = new CreateUserResponse() 
            { User=user, Token=token}, IsSuccess = true, StatusCode = 201, Message = "User Created!" };
        }
        else
        {
            return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 500, Message = "User failed to Create!" };
        }
    }

    public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
    {
        var user = await _userManager.FindByNameAsync(loginModel.Username);
        if(user != null)
        {
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
            if (user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = token,
                        IsTwoFactorEnable = user.TwoFactorEnabled
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"OTP sent to the email  {user.Email}"
                };
            }
            else
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse()
                    {
                        User = user,
                        Token = string.Empty,
                        IsTwoFactorEnable = user.TwoFactorEnabled
                    },
                    StatusCode = 200,
                    Message = $"2FA is not enabled"
                };
            }
        }
        else
        {
            return new ApiResponse<LoginOtpResponse>
            {
                IsSuccess = false,
                StatusCode = 404,
                Message = "User does not exist."
            };
        }
        
        
    }

    public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
    {
        var accessToken = tokens.AccessToken;
        var refreshToken = tokens.RefreshToken;

        var principal = GetClaimsPrincipal(accessToken.Token);
        var user = await _userManager.FindByNameAsync(principal.Identity.Name);

        if(refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.UtcNow)
        {
            return new ApiResponse<LoginResponse>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = "Token invalid or expired"
            };
        }

        var response = await GetJwtTokenAsync(user);
        return response;
    }

    public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var userRoles = await _userManager.GetRolesAsync(user);
        foreach(var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        var jwtToken = GetToken(authClaims); // access token 
        var refreshToken = GenerateRefreshToken();
        _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int tokenValidityInMinutes);

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(tokenValidityInMinutes);

        await _userManager.UpdateAsync(user);

        return new ApiResponse<LoginResponse>
        {
            Response = new LoginResponse()
            {
                AccessToken = new TokenType()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpiryTokenDate = jwtToken.ValidTo
                },
                RefreshToken = new TokenType()
                {
                    Token = user.RefreshToken,
                    ExpiryTokenDate = user.RefreshTokenExpiry
                }
            },
            IsSuccess = true,
            StatusCode = 200,
            Message = "Token created"
        };
    }
    #region PrivateMehtods

    private string GenerateRefreshToken()
    {
        var randomNumber = new Byte[64];
        var range = RandomNumberGenerator.Create();
        range.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
            ValidateLifetime = false,
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);
        return principal;
    }

    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

        // Calculate expiration time in UTC directly
        var expirationTimeUtc = DateTime.UtcNow.AddHours(tokenValidityInMinutes);

        // Now directly use expirationTimeUtc in the JWT token
        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: expirationTimeUtc, // Use UTC expiration time
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));
        //var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        //_ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
        //var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
        //var localTimeZone = TimeZoneInfo.Local;
        //var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeToUtc(expirationTimeUtc, localTimeZone);

        //var token = new JwtSecurityToken(
        //    issuer: _configuration["JWT:ValidIssuer"],
        //    audience: _configuration["JWT:ValidAudience"],
        //    expires: expirationTimeInLocalTimeZone,
        //    claims: authClaims,
        //    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

        return token;
    }
    #endregion
}

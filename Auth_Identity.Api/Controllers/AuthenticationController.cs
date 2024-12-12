using Auth_Identity.Api.Models;
using Auth_Identity.Data.Models;
using Auth_Identity.Service.Models;
using Auth_Identity.Service.Models.Authentication.Login;
using Auth_Identity.Service.Models.Authentication.SignUp;
using Auth_Identity.Service.Models.Authentication.User;
using Auth_Identity.Service.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Auth_Identity.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _userManagement;

        public AuthenticationController(IConfiguration configuration,
            RoleManager<IdentityRole> roleManager,
            UserManager<ApplicationUser> userManager,
            IEmailService emailService,
            SignInManager<ApplicationUser> signInManager,
            IUserManagement userManagement)
        {
            _configuration = configuration;
            _roleManager = roleManager;
            _userManager = userManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _userManagement = userManagement;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegiterUser registerUser)
        {
            var tokenResponse = await _userManagement.CreateUserWithTokenAsync(registerUser);

            if (tokenResponse.IsSuccess)
            {
                await _userManagement.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication",
                    new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                            new Models.Response { Status = "Success", Message = "Email verified successfully!" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                            new Models.Response {Message = tokenResponse.Message, IsSuccess = false });
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Models.Response { Status = "Success", Message = "Email verified successfully!" });
                }
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                new Models.Response { Status = "Error", Message = "This user doesn't exist!" });
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _userManagement.GetOtpByLoginAsync(loginModel);
            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;

                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "Otp Confirmation", token);
                    _emailService.SendEmail(message);

                    return StatusCode(StatusCodes.Status200OK,
                        new Models.Response {IsSuccess = loginOtpResponse.IsSuccess, Status = "Success", Message = $"We have sent an OTP to your email {user.Email}" });
                } 
                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password) && user.EmailConfirmed is not false)
                {

                    var serviceResponse = await _userManagement.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);
                //    var authCalims = new List<Claim>
                //{
                //    new Claim(ClaimTypes.Name, user.UserName),
                //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                //};

                //    var userRoles = await _userManager.GetRolesAsync(user);
                //    foreach (var role in userRoles)
                //    {
                //        authCalims.Add(new Claim(ClaimTypes.Role, role));
                //    }

                //    //if (user.TwoFactorEnabled)
                //    //{
                //    //    await _signInManager.SignOutAsync();
                //    //    await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);
                //    //    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                //    //    var message = new Message(new string[] { user.Email! }, "Otp Confirmation", token);
                //    //    _emailService.SendEmail(message);

                //    //    return StatusCode(StatusCodes.Status200OK,
                //    //        new Response { Status = "Success", Message = $"We have sent an OTP to your email {user.Email}" });
                //    //}

                //    var jwtToken = GetToken(authCalims);

                //    return Ok(new
                //    {
                //        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                //        expiration = jwtToken.ValidTo
                //    });
                }
            }
            

            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if(signIn.Succeeded)
            {
                if (user != null)
                {

                    var serviceResponse = await _userManagement.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);
                    //    var authCalims = new List<Claim>
                    //{
                    //    new Claim(ClaimTypes.Name, user.UserName),
                    //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    //};

                    //    var userRoles = await _userManager.GetRolesAsync(user);
                    //    foreach (var role in userRoles)
                    //    {
                    //        authCalims.Add(new Claim(ClaimTypes.Role, role));
                    //    }

                    //    var jwtToken = GetToken(authCalims);

                    //    return Ok(new
                    //    {
                    //        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    //        expiration = jwtToken.ValidTo
                    //    });
                }                
            }

            return StatusCode(StatusCodes.Status404NotFound,
                    new Models.Response { Status = "Error", Message = $"Invalid code" });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _userManagement.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = "Invalid Code" });
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new {token, email = user.Email}, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "ForgotPasswordLink", forgotPasswordLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Models.Response { Status = "Success", Message = $"Password changed request is sent on Email {user.Email}. Please open your email & Click it!" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                    new Models.Response { Status = "Error", Message = $"Couldn't send link to email, please try again" });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new { model });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if(user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if(!resetPassResult.Succeeded)
                {
                    foreach(var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                    new Models.Response { Status = "Success", Message = $"Password has been changed" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                    new Models.Response { Status = "Error", Message = $"Couldn't send link to email, please try again" });
        }

        
        
    }
}

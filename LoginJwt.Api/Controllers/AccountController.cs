using Microsoft.AspNetCore.Mvc;
using LoginJwt.Api.Models;
using LoginJwt.Authorization.Encryptors;
using LoginJwt.Authorization.Models;
using LoginJwt.Authorization.Tokenizers;
using LoginJwt.Tools.Extensions;
using System.Linq;
using System.Threading.Tasks;

namespace LoginJwt.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> _userManager;

        public AccountController(Microsoft.AspNetCore.Identity.UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] EmailPasswordModel model)
        {
            if (!model.Email.IsValidEmail())
            {
                return BadRequest();
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errorMessages = result.Errors.Select(e => e.Description).Aggregate((en, enn) => en + ", " + enn);
                return Conflict(new { Status = "Error", Message = errorMessages });
            }

            //await SendEmailConfirmationAsync(model, user); TODO send email confirmation
            var refreshToken = AesCryptor.EncryptStringAes(user.Id, RefreshtokenKey.Value, RefreshtokenKey.IV);
            var jwtToken = JwtTokenizer.GenerateJwtToken(user.Id, user.Email);
            //CreateAuthenticatedCookie(jwtToken);
            return Ok(new { userId = user.Id, Token = jwtToken, refreshtoken = refreshToken });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] EmailPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid user name or password");
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Conflict("Bad user name password combination");
            }

            if (!await _userManager.CheckPasswordAsync(user, model.Password))
            {
                return Conflict("Bad user name password combination");
            }
            //TODO: implement user account lockout to avoid guess password with brute force

            var refreshToken = AesCryptor.EncryptStringAes(user.Id, RefreshtokenKey.Value, RefreshtokenKey.IV);
            var jwtToken = JwtTokenizer.GenerateJwtToken(user.Id, user.Email);
            //CreateAuthenticatedCookie(jwtToken);
            return Ok(new { userId = user.Id, Token = jwtToken, refreshtoken = refreshToken });
        }
    }
}

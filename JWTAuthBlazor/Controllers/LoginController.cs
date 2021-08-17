using JWTAuthBlazor.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthBlazor.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private IConfiguration _config;

        public LoginController(IConfiguration config)
        {
            _config = config;
        }
        [AllowAnonymous]
        [HttpGet]
        public IActionResult Login(string userId, string password)
        {
            UserModel model = new UserModel();
            model.UserName = userId;
            model.Password = password;
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(model);
            if (user is null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });
            }
            return response;
        }

        [Authorize(Roles ="Admin")]
        [HttpPost]
        public IActionResult Post([FromBody] string value)
        {
            try
            {
                return Ok(value);
            }
            catch (Exception)
            {

                return NotFound();
            }
        }

        private string GenerateJSONWebToken(UserModel user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                 issuer:_config["Jwt:Issuer"],
                 audience: _config["Jwt:Issuer"],
                 claims,
                 expires:DateTime.Now.AddMinutes(20),
                 signingCredentials:credentials
                );
            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);
            return encodedToken;
        }

        private UserModel AuthenticateUser(UserModel model)
        {
            var user = new UserModel();
            if (model.UserName=="yalcin" && model.Password=="123")
            {
                //Hard coded user
                 user = new UserModel { UserName = "AshProgHelp", Email= "ashproghelp.com", Password="123",  Role="Admin" };
            }
            return user;
        }
    }
}

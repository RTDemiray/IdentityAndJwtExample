using IdentityAndJwtExample.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAndJwtExample.Infrastucture
{
    public class TokenHandler
    {
        private readonly IConfiguration _configuration;

        public TokenHandler(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public LoginResponseModel CreateToken(LoginModel model)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(_configuration["Token:SecurityKey"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = _configuration["Token:Audience"],
                Issuer = _configuration["Token:Issuer"],
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("EMail", model.Email)
                }),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var loginResponseModel = new LoginResponseModel { Email = model.Email, Token = tokenHandler.WriteToken(token) };
            return loginResponseModel;
        }
    }
}

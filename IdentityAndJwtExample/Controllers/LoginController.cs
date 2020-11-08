using System;
using System.Threading.Tasks;
using IdentityAndJwtExample.Infrastucture;
using IdentityAndJwtExample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace IdentityAndJwtExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly UserManager<AppUser> _userManager;

        public LoginController(IConfiguration configuration, SignInManager<AppUser> signInManager = null, UserManager<AppUser> userManager = null)
        {
            _configuration = configuration;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        [Authorize]
        [HttpPost(nameof(Create))]
        public async Task<IActionResult> Create(CreateUserModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var userControl = _userManager.FindByEmailAsync(model.Email);
                    if (userControl.Result != null)
                        return BadRequest(new { Message = "Sistemde aynı email'e kayıtlı kullanıcı bulunmaktadır!", IsSuccess = false });

                    var user = new AppUser { UserName = model.UserName, Email = model.Email };
                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        return Created(new Uri(Request.Path, UriKind.Relative), model);
                    }
                    return BadRequest(new { Message = "Kullanıcı kayıdı oluşturulamadı!", IsSuccess = false });
                }
                return BadRequest(new { Message = "Hata oluştu!", IsSuccess = false });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = $"Hata: {ex.Message}", IsSuccess = false });
            }
        }

        [HttpPost]
        public async Task<IActionResult> Index(LoginModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var userControl = await _userManager.FindByEmailAsync(model.Email);
                    if (userControl == null)
                        return NotFound(new { Message = "Böyle bir kullanıcı bulunamadı!", IsSuccess = false });

                    var result = await _signInManager.PasswordSignInAsync(userControl, model.Password, false, false);
                    if (result.Succeeded)
                    {
                        var tokenHandler = new TokenHandler(_configuration);
                        var user = tokenHandler.CreateToken(model);
                        if (user != null)
                            return Ok(user);
                        return BadRequest(new { Message = "Token oluşturulamadı!", IsSuccess = false });

                    }    

                    return BadRequest(new { Message = "Kullanıcı adı veya şifre hatalı!", IsSuccess = false });
                }
                return BadRequest(new { Message = "Hata oluştu!", IsSuccess = false });
            }
            catch (Exception ex)
            {
                return Ok(new { Message = $"Hata: {ex.Message}", IsSuccess = false });
            }
        }
    }
}

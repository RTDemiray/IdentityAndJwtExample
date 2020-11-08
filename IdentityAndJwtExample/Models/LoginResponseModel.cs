using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityAndJwtExample.Models
{
    public class LoginResponseModel
    {
        public string Email { get; set; }
        public string Token { get; set; }
    }
}

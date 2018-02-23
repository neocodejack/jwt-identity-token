using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Auth.Identity.Entities;
using Auth.Identity.Jwt;
using Auth.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Auth.Identity.Helpers;
using Newtonsoft.Json;

namespace Auth.Identity.Controllers
{
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        private readonly UserManager<MyUser> _userManager;
        private readonly IJwtFactory _jwtFactory;
        private readonly JwtIssuerOptions _issuerOptions;

        public ValuesController(UserManager<MyUser> userManager, IJwtFactory jwtFactory, IOptions<JwtIssuerOptions> issuerOptions)
        {
            _userManager = userManager;
            _jwtFactory = jwtFactory;
            _issuerOptions = issuerOptions.Value;
        }

        [HttpPost]
        [Route("/login")]
        public async Task<IActionResult> Post([FromBody]string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var claimsIdentity = _jwtFactory.CreateClaimsIdentity(userName, user.Id);
            var jwt = Token.GenerateJwt(claimsIdentity, _jwtFactory, userName, _issuerOptions, new JsonSerializerSettings { Formatting = Formatting.Indented });

            return new OkObjectResult(jwt);
        }
        
    }
}

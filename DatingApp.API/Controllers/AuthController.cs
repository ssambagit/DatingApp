using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers {
    [Route ("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController (IAuthRepository repo, IConfiguration config) {
            _config = config;
            _repo = repo;
        }

        [HttpPost ("register")]
        public async Task<IActionResult> Register (UserForRegisterDto userForRegisterDto) {

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower ();
            if (await _repo.UserExists (userForRegisterDto.Username))
                return BadRequest ("username already exists");

            var userToCreate = new User {
                UserName = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register (userToCreate, userForRegisterDto.Password);

            return StatusCode (201);
        }

        [HttpPost ("login")]
        public async Task<IActionResult> Login (UserForLoginDto userForLoginDto) {

            var userFromRepo = await _repo.Login (userForLoginDto.Username.ToLower(), userForLoginDto.Password); // verify login credential are there in the database

            if (userFromRepo == null)
                return Unauthorized (); // if the credential doesn't exists return unauthorized
        // now here we are building token with two item one is user id, other one is user's user name
            var claims = new [] {
                new Claim (ClaimTypes.NameIdentifier, userFromRepo.Id.ToString ()),
                new Claim (ClaimTypes.Name, userFromRepo.UserName)
            };
            //once above claims are valid then the server needs to sign in the user. Below here we are creating security key when sign in we use this key plus the user credential. HmachSha512Signature is used to encript the key with hashing algorithm
            var key = new SymmetricSecurityKey (Encoding.UTF8.GetBytes (_config.GetSection ("AppSettings:Token").Value));

            // Below we encripting the key with hashing algorithm
            var creds = new SigningCredentials (key, SecurityAlgorithms.HmacSha512Signature) ;
            
           // below we are creating token using SecurityTokenDescriptor and passing our claims
            var tokenDescriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity (claims),
                Expires = DateTime.Now.AddDays (1),
                SigningCredentials = creds
            };
            
            // JwtSecurityTokenHandler will create the token using token
            var tokenHandler = new JwtSecurityTokenHandler ();
            var token = tokenHandler.CreateToken (tokenDescriptor);

            return Ok (new 
            { 
                token = tokenHandler.WriteToken (token)
             });
        }
    }
}
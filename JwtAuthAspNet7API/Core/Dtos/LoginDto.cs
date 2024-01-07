using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7API.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "User Name is require")]
        public string UserName { get; set; }

      
        [Required(ErrorMessage = "Password Name is require")]
        public string Password { get; set; }
    }
}

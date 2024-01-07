using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7API.Core.Dtos
{
    public class RegisterDto
    {
        [Required(ErrorMessage ="User Name is require")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "Email Name is require")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password Name is require")]
        public string Password { get; set; }
    }
}

using System.ComponentModel.DataAnnotations;

namespace JwtAuthAspNet7API.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "User Name is require")]
        public string UserName { get; set; }

    }
}

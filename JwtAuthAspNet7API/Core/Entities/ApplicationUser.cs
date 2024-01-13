using Microsoft.AspNetCore.Identity;

namespace JwtAuthAspNet7API.Core.Entities
{
    public class ApplicationUser:IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}

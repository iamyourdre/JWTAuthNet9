using JWTAuthNet9.Entities;
using JWTAuthNet9.Models;

namespace JWTAuthNet9.Services
{
    public interface IAuthService
    {
        Task<User> RegisterAsync(UserDto request);
        Task<string> LoginAsync(UserDto request);
    }
}

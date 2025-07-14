using JWTAuthNet9.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthNet9.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users {  get; set; } = null!;

    }
}

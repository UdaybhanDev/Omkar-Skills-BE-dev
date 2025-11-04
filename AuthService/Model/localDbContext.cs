using Microsoft.EntityFrameworkCore;

namespace AuthService.Model
{
    public class localDbContext : DbContext
    {
        public localDbContext(DbContextOptions<localDbContext> options) : base(options)
        {
            
        }

        public DbSet<RegisterDTO> registerDTOs { get; set; }

    }
}

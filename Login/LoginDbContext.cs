using Microsoft.EntityFrameworkCore;
using Login.Model;
using System;


namespace Login
{
    public class LoginDbContext : DbContext
    {
        public LoginDbContext(DbContextOptions<LoginDbContext> options)
            : base(options)
        {
        }
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("Users");
                entity.HasKey(e => e.UserId);
                entity.Property(e => e.UserName).HasColumnType("varchar(25)");
                entity.Property(e => e.Password).HasColumnType("varbinary(max)");
            });
} }     }

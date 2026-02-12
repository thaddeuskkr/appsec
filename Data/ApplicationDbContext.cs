using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<PasswordHistory> PasswordHistories => Set<PasswordHistory>();

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    public DbSet<ActiveSession> ActiveSessions => Set<ActiveSession>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(x => x.FirstName).HasMaxLength(100).IsRequired();
            entity.Property(x => x.LastName).HasMaxLength(100).IsRequired();
            entity.Property(x => x.EncryptedCreditCard).HasColumnType("longtext").IsRequired();
            entity.Property(x => x.EncryptedMobileNo).HasColumnType("longtext").IsRequired();
            entity.Property(x => x.EncryptedBillingAddress).HasColumnType("longtext").IsRequired();
            entity.Property(x => x.EncryptedShippingAddress).HasColumnType("longtext").IsRequired();
            entity.Property(x => x.PhotoFileName).HasMaxLength(260);
            entity.Property(x => x.CurrentSessionToken).HasMaxLength(128);
            entity.Property(x => x.PasswordChangedAtUtc).IsRequired();
            entity.HasIndex(x => x.NormalizedEmail).IsUnique();
        });

        builder.Entity<PasswordHistory>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.UserId).HasMaxLength(450).IsRequired();
            entity.Property(x => x.PasswordHash).HasColumnType("longtext").IsRequired();
            entity.HasIndex(x => new { x.UserId, x.CreatedAtUtc });
            entity.HasOne(x => x.User)
                .WithMany(u => u.PasswordHistories)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<AuditLog>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Action).HasMaxLength(100).IsRequired();
            entity.Property(x => x.Outcome).HasMaxLength(50).IsRequired();
            entity.Property(x => x.IpAddress).HasMaxLength(100);
            entity.Property(x => x.UserAgent).HasMaxLength(512);
            entity.Property(x => x.Details).HasColumnType("longtext");
            entity.HasIndex(x => x.CreatedAtUtc);
            entity.HasIndex(x => x.UserId);
            entity.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.SetNull);
        });

        builder.Entity<ActiveSession>(entity =>
        {
            entity.HasKey(x => x.SessionToken);
            entity.Property(x => x.SessionToken).HasMaxLength(128).IsRequired();
            entity.Property(x => x.UserId).HasMaxLength(255).IsRequired();
            entity.Property(x => x.CreatedAtUtc).IsRequired();
            entity.Property(x => x.LastSeenUtc).IsRequired();
            entity.Property(x => x.ExpiresAtUtc).IsRequired();
            entity.HasIndex(x => x.UserId);
            entity.HasIndex(x => x.ExpiresAtUtc);
            entity.HasOne(x => x.User)
                .WithMany(u => u.ActiveSessions)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}

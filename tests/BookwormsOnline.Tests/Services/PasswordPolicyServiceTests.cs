using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Tests.Services;

public class PasswordPolicyServiceTests
{
    private static PasswordPolicyService CreateService(ApplicationDbContext dbContext)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new SecurityPolicyOptions
        {
            PasswordMinAgeMinutes = 5,
            PasswordMaxAgeDays = 90,
            PasswordHistoryCount = 2
        });

        return new PasswordPolicyService(dbContext, options, new PasswordHasher<ApplicationUser>());
    }

    [Fact]
    public void IsPasswordExpired_ReturnsTrue_WhenBeyondMaxAge()
    {
        var dbContext = CreateDbContext();
        var service = CreateService(dbContext);
        var user = new ApplicationUser
        {
            PasswordChangedAtUtc = DateTimeOffset.UtcNow.AddDays(-91)
        };

        var expired = service.IsPasswordExpired(user);

        Assert.True(expired);
    }

    [Fact]
    public void CanChangePassword_ReturnsFalse_WhenWithinMinAge()
    {
        var dbContext = CreateDbContext();
        var service = CreateService(dbContext);
        var user = new ApplicationUser
        {
            PasswordChangedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-2)
        };

        var allowed = service.CanChangePassword(user, out var remaining);

        Assert.False(allowed);
        Assert.True(remaining.TotalMinutes > 0);
    }

    [Fact]
    public async Task IsPasswordReusedAsync_ReturnsTrue_ForCurrentPassword()
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);
        var hasher = new PasswordHasher<ApplicationUser>();
        var user = new ApplicationUser { Id = Guid.NewGuid().ToString("N") };
        user.PasswordHash = hasher.HashPassword(user, "Password@123");

        var reused = await service.IsPasswordReusedAsync(user, "Password@123");

        Assert.True(reused);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;

        return new ApplicationDbContext(options);
    }
}

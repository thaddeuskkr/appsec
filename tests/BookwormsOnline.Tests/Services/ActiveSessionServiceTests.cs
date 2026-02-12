using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Tests.Services;

public class ActiveSessionServiceTests
{
    [Fact]
    public async Task StartSessionAsync_AllowsRefresh()
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);

        await service.StartSessionAsync("user-1", "token-1");

        var refreshed = await service.RefreshSessionAsync("token-1");

        Assert.True(refreshed);
    }

    [Fact]
    public async Task RefreshSessionAsync_ReturnsFalse_WhenSessionMissing()
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);

        var refreshed = await service.RefreshSessionAsync("unknown-token");

        Assert.False(refreshed);
    }

    [Fact]
    public async Task RefreshSessionAsync_ReturnsFalse_WhenSessionExpired()
    {
        await using var dbContext = CreateDbContext();
        dbContext.ActiveSessions.Add(new ActiveSession
        {
            SessionToken = "token-expired",
            UserId = "user-2",
            CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-20),
            LastSeenUtc = DateTimeOffset.UtcNow.AddMinutes(-20),
            ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        await dbContext.SaveChangesAsync();

        var service = CreateService(dbContext);
        var refreshed = await service.RefreshSessionAsync("token-expired");

        Assert.False(refreshed);
        Assert.Empty(dbContext.ActiveSessions);
    }

    [Fact]
    public async Task EndSessionAsync_RemovesSession()
    {
        await using var dbContext = CreateDbContext();
        var service = CreateService(dbContext);
        await service.StartSessionAsync("user-3", "token-3");

        await service.EndSessionAsync("token-3");

        Assert.Empty(dbContext.ActiveSessions);
    }

    private static ActiveSessionService CreateService(ApplicationDbContext dbContext)
    {
        var options = Microsoft.Extensions.Options.Options.Create(new SecurityPolicyOptions
        {
            SessionIdleTimeoutMinutes = 5
        });

        return new ActiveSessionService(dbContext, options);
    }

    private static ApplicationDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString("N"))
            .Options;

        return new ApplicationDbContext(options);
    }
}

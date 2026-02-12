using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class ActiveSessionService : IActiveSessionService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IOptions<SecurityPolicyOptions> _policyOptions;

    public ActiveSessionService(ApplicationDbContext dbContext, IOptions<SecurityPolicyOptions> policyOptions)
    {
        _dbContext = dbContext;
        _policyOptions = policyOptions;
    }

    public async Task StartSessionAsync(string userId, string sessionToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(sessionToken))
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        var expiresAt = now.AddMinutes(GetIdleTimeoutMinutes());
        var existing = await _dbContext.ActiveSessions
            .SingleOrDefaultAsync(x => x.SessionToken == sessionToken, cancellationToken);

        if (existing is null)
        {
            _dbContext.ActiveSessions.Add(new ActiveSession
            {
                SessionToken = sessionToken,
                UserId = userId,
                CreatedAtUtc = now,
                LastSeenUtc = now,
                ExpiresAtUtc = expiresAt
            });
        }
        else
        {
            existing.UserId = userId;
            existing.LastSeenUtc = now;
            existing.ExpiresAtUtc = expiresAt;
        }

        var expiredSessions = await _dbContext.ActiveSessions
            .Where(x => x.ExpiresAtUtc <= now && x.SessionToken != sessionToken)
            .ToListAsync(cancellationToken);

        if (expiredSessions.Count > 0)
        {
            _dbContext.ActiveSessions.RemoveRange(expiredSessions);
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<bool> RefreshSessionAsync(string sessionToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        var session = await _dbContext.ActiveSessions
            .SingleOrDefaultAsync(x => x.SessionToken == sessionToken, cancellationToken);

        if (session is null)
        {
            return false;
        }

        if (session.ExpiresAtUtc <= now)
        {
            _dbContext.ActiveSessions.Remove(session);
            await _dbContext.SaveChangesAsync(cancellationToken);
            return false;
        }

        session.LastSeenUtc = now;
        session.ExpiresAtUtc = now.AddMinutes(GetIdleTimeoutMinutes());
        await _dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task EndSessionAsync(string sessionToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return;
        }

        var session = await _dbContext.ActiveSessions
            .SingleOrDefaultAsync(x => x.SessionToken == sessionToken, cancellationToken);
        if (session is null)
        {
            return;
        }

        _dbContext.ActiveSessions.Remove(session);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private int GetIdleTimeoutMinutes()
    {
        return Math.Max(1, _policyOptions.Value.SessionIdleTimeoutMinutes);
    }
}

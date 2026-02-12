using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class PasswordPolicyService : IPasswordPolicyService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly SecurityPolicyOptions _options;
    private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

    public PasswordPolicyService(
        ApplicationDbContext dbContext,
        IOptions<SecurityPolicyOptions> options,
        IPasswordHasher<ApplicationUser> passwordHasher)
    {
        _dbContext = dbContext;
        _options = options.Value;
        _passwordHasher = passwordHasher;
    }

    public bool IsPasswordExpired(ApplicationUser user)
    {
        if (user.ForcePasswordChange)
        {
            return true;
        }

        var expiresAt = user.PasswordChangedAtUtc.AddDays(_options.PasswordMaxAgeDays);
        return DateTimeOffset.UtcNow >= expiresAt;
    }

    public bool CanChangePassword(ApplicationUser user, out TimeSpan remaining)
    {
        var eligibleAt = user.PasswordChangedAtUtc.AddMinutes(_options.PasswordMinAgeMinutes);
        if (DateTimeOffset.UtcNow >= eligibleAt)
        {
            remaining = TimeSpan.Zero;
            return true;
        }

        remaining = eligibleAt - DateTimeOffset.UtcNow;
        return false;
    }

    public async Task<bool> IsPasswordReusedAsync(
        ApplicationUser user,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            var currentCheck = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, newPassword);
            if (currentCheck is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded)
            {
                return true;
            }
        }

        var hashes = await _dbContext.PasswordHistories
            .Where(x => x.UserId == user.Id)
            .OrderByDescending(x => x.CreatedAtUtc)
            .Take(_options.PasswordHistoryCount)
            .Select(x => x.PasswordHash)
            .ToListAsync(cancellationToken);

        return hashes.Any(hash =>
        {
            var result = _passwordHasher.VerifyHashedPassword(user, hash, newPassword);
            return result is PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
        });
    }

    public async Task RecordPasswordHashAsync(string userId, string passwordHash, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(passwordHash))
        {
            return;
        }

        _dbContext.PasswordHistories.Add(new PasswordHistory
        {
            UserId = userId,
            PasswordHash = passwordHash,
            CreatedAtUtc = DateTimeOffset.UtcNow
        });

        await _dbContext.SaveChangesAsync(cancellationToken);

        var history = await _dbContext.PasswordHistories
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToListAsync(cancellationToken);

        var toDelete = history.Skip(_options.PasswordHistoryCount).ToList();
        if (toDelete.Count == 0)
        {
            return;
        }

        _dbContext.PasswordHistories.RemoveRange(toDelete);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public void MarkPasswordChanged(ApplicationUser user)
    {
        user.PasswordChangedAtUtc = DateTimeOffset.UtcNow;
        user.ForcePasswordChange = false;
    }
}

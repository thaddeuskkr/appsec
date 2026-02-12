using BookwormsOnline.Models;

namespace BookwormsOnline.Services;

public interface IPasswordPolicyService
{
    bool IsPasswordExpired(ApplicationUser user);

    bool CanChangePassword(ApplicationUser user, out TimeSpan remaining);

    Task<bool> IsPasswordReusedAsync(ApplicationUser user, string newPassword, CancellationToken cancellationToken = default);

    Task RecordPasswordHashAsync(string userId, string passwordHash, CancellationToken cancellationToken = default);

    void MarkPasswordChanged(ApplicationUser user);
}

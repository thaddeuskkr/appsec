namespace BookwormsOnline.Services;

public interface IActiveSessionService
{
    Task StartSessionAsync(string userId, string sessionToken, CancellationToken cancellationToken = default);

    Task<bool> RefreshSessionAsync(string sessionToken, CancellationToken cancellationToken = default);

    Task EndSessionAsync(string sessionToken, CancellationToken cancellationToken = default);
}

namespace BookwormsOnline.Services;

public interface IAuditLogService
{
    Task LogAsync(
        string action,
        string outcome,
        string? userId = null,
        string? details = null,
        CancellationToken cancellationToken = default);
}

namespace BookwormsOnline.Services;

public interface IRecaptchaService
{
    Task<RecaptchaVerificationResult> VerifyAsync(
        string token,
        string expectedAction,
        string? remoteIp,
        CancellationToken cancellationToken = default);
}

public sealed record RecaptchaVerificationResult(bool Success, double Score, string? ErrorCode);

namespace BookwormsOnline.Services;

public interface IAppUrlService
{
    string BuildPageUrl(string pagePath, object? values = null);
}

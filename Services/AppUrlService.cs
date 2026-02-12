using System.Globalization;
using BookwormsOnline.Options;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class AppUrlService : IAppUrlService
{
    private readonly Uri _publicBaseUri;

    public AppUrlService(IOptions<AppUrlOptions> options)
    {
        if (!Uri.TryCreate(options.Value.PublicBaseUrl, UriKind.Absolute, out var parsed))
        {
            throw new InvalidOperationException("AppUrl:PublicBaseUrl must be a valid absolute URL.");
        }

        _publicBaseUri = parsed;
    }

    public string BuildPageUrl(string pagePath, object? values = null)
    {
        if (string.IsNullOrWhiteSpace(pagePath))
        {
            throw new ArgumentException("Page path cannot be empty.", nameof(pagePath));
        }

        var normalizedPath = pagePath.StartsWith("/", StringComparison.Ordinal) ? pagePath : $"/{pagePath}";
        var pageUri = new Uri(_publicBaseUri, normalizedPath);

        var routeValues = new RouteValueDictionary(values);
        if (routeValues.Count == 0)
        {
            return pageUri.ToString();
        }

        var queryValues = routeValues
            .Where(x => x.Value is not null)
            .ToDictionary(
                x => x.Key,
                x => (string?)Convert.ToString(x.Value, CultureInfo.InvariantCulture));

        return QueryHelpers.AddQueryString(pageUri.ToString(), queryValues);
    }
}

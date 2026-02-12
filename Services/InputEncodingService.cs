using System.Net;

namespace BookwormsOnline.Services;

public static class InputEncodingService
{
    public static string EncodeForStorage(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        return WebUtility.HtmlEncode(input.Trim());
    }

    public static string DecodeFromStorage(string? storedValue)
    {
        if (string.IsNullOrWhiteSpace(storedValue))
        {
            return string.Empty;
        }

        return WebUtility.HtmlDecode(storedValue);
    }
}

using System.Net;
using System.Text.Encodings.Web;
using System.Text.Unicode;

namespace BookwormsOnline.Services;

public static class InputEncodingService
{
    private static readonly HtmlEncoder StorageHtmlEncoder = CreateStorageEncoder();

    public static string EncodeForStorage(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        return StorageHtmlEncoder.Encode(input.Trim());
    }

    public static string DecodeFromStorage(string? storedValue)
    {
        if (string.IsNullOrWhiteSpace(storedValue))
        {
            return string.Empty;
        }

        return WebUtility.HtmlDecode(storedValue);
    }

    private static HtmlEncoder CreateStorageEncoder()
    {
        var settings = new TextEncoderSettings(UnicodeRanges.BasicLatin);
        settings.ForbidCharacter('/');
        settings.ForbidCharacter('\\');
        return HtmlEncoder.Create(settings);
    }
}

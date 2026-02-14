using System.Net;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;

namespace BookwormsOnline.Services;

public static class InputEncodingService
{
    public static string EncodeForStorage(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var trimmed = input.Trim();
        var buffer = new StringBuilder(trimmed.Length * 2);

        foreach (var rune in trimmed.EnumerateRunes())
        {
            if (ShouldEncodeAsEntity(rune))
            {
                buffer.Append("&#x");
                buffer.Append(rune.Value.ToString("X", CultureInfo.InvariantCulture));
                buffer.Append(';');
                continue;
            }

            buffer.Append(HtmlEncoder.Default.Encode(rune.ToString()));
        }

        return buffer.ToString();
    }

    public static string DecodeFromStorage(string? storedValue)
    {
        if (string.IsNullOrWhiteSpace(storedValue))
        {
            return string.Empty;
        }

        return WebUtility.HtmlDecode(storedValue);
    }

    private static bool ShouldEncodeAsEntity(Rune rune)
    {
        return Rune.GetUnicodeCategory(rune) is
            UnicodeCategory.ConnectorPunctuation or
            UnicodeCategory.DashPunctuation or
            UnicodeCategory.OpenPunctuation or
            UnicodeCategory.ClosePunctuation or
            UnicodeCategory.InitialQuotePunctuation or
            UnicodeCategory.FinalQuotePunctuation or
            UnicodeCategory.OtherPunctuation or
            UnicodeCategory.MathSymbol or
            UnicodeCategory.CurrencySymbol or
            UnicodeCategory.ModifierSymbol or
            UnicodeCategory.OtherSymbol;
    }
}

using BookwormsOnline.Services;

namespace BookwormsOnline.Tests.Services;

public class InputEncodingServiceTests
{
    [Fact]
    public void EncodeForStorage_EncodesHtmlSpecialCharacters_AndSlashes()
    {
        const string input = "  Tom & Jerry <script>alert('x')</script> / \\\\ &nbsp;  ";

        var encoded = InputEncodingService.EncodeForStorage(input);

        Assert.Contains("&amp;", encoded, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", encoded, StringComparison.Ordinal);
        Assert.DoesNotContain(" / ", encoded, StringComparison.Ordinal);
        Assert.DoesNotContain("\\\\", encoded, StringComparison.Ordinal);

        var decoded = InputEncodingService.DecodeFromStorage(encoded);
        Assert.Equal("Tom & Jerry <script>alert('x')</script> / \\\\ &nbsp;", decoded);
    }

    [Fact]
    public void DecodeFromStorage_DecodesEncodedEntities()
    {
        const string encoded = "Tom &amp; Jerry &lt;b&gt;bold&lt;/b&gt; &amp;nbsp;";

        var decoded = InputEncodingService.DecodeFromStorage(encoded);

        Assert.Equal("Tom & Jerry <b>bold</b> &nbsp;", decoded);
    }
}

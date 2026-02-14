using BookwormsOnline.Services;

namespace BookwormsOnline.Tests.Services;

public class InputEncodingServiceTests
{
    [Fact]
    public void EncodeForStorage_EncodesAllPunctuationAndSymbols()
    {
        const string input = "  Tom & Jerry <script>alert('x')</script> / \\\\ % ! ?  ";

        var encoded = InputEncodingService.EncodeForStorage(input);

        Assert.Contains("&#x26;", encoded, StringComparison.Ordinal); // &
        Assert.Contains("&#x3C;", encoded, StringComparison.Ordinal); // <
        Assert.Contains("&#x3E;", encoded, StringComparison.Ordinal); // >
        Assert.Contains("&#x2F;", encoded, StringComparison.Ordinal); // /
        Assert.Contains("&#x5C;", encoded, StringComparison.Ordinal); // \
        Assert.Contains("&#x25;", encoded, StringComparison.Ordinal); // %
        Assert.Contains("&#x21;", encoded, StringComparison.Ordinal); // !
        Assert.Contains("&#x3F;", encoded, StringComparison.Ordinal); // ?

        var decoded = InputEncodingService.DecodeFromStorage(encoded);
        Assert.Equal("Tom & Jerry <script>alert('x')</script> / \\\\ % ! ?", decoded);
    }

    [Fact]
    public void DecodeFromStorage_DecodesEncodedEntities()
    {
        const string encoded = "Tom &amp; Jerry &lt;b&gt;bold&lt;/b&gt; &amp;nbsp;";

        var decoded = InputEncodingService.DecodeFromStorage(encoded);

        Assert.Equal("Tom & Jerry <b>bold</b> &nbsp;", decoded);
    }

    [Fact]
    public void DecodeFromStorage_DecodesHexAndDecimalEntities()
    {
        const string encoded = "A&#x2F;B&#47;C&#x5C;D&#92;E&#x25;F";

        var decoded = InputEncodingService.DecodeFromStorage(encoded);

        Assert.Equal("A/B/C\\D\\E%F", decoded);
    }

    [Fact]
    public void DecodeFromStorage_ReturnsOriginalValue_WhenNoEntitiesPresent()
    {
        const string plainText = "Normal Name 123";

        var decoded = InputEncodingService.DecodeFromStorage(plainText);

        Assert.Equal("Normal Name 123", decoded);
    }

    [Fact]
    public void EncodeDecode_RoundTripsUnicodeAndPunctuation()
    {
        const string input = "Émilie 张三 - team #1 / QA";

        var encoded = InputEncodingService.EncodeForStorage(input);
        var decoded = InputEncodingService.DecodeFromStorage(encoded);

        Assert.Equal(input, decoded);
    }
}

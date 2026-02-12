using BookwormsOnline.Services;

namespace BookwormsOnline.Tests.Services;

public class InputEncodingServiceTests
{
    [Fact]
    public void EncodeForStorage_EncodesHtmlSpecialCharacters()
    {
        const string input = "  Tom & Jerry <script>alert('x')</script> &nbsp;  ";

        var encoded = InputEncodingService.EncodeForStorage(input);

        Assert.Equal("Tom &amp; Jerry &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp;nbsp;", encoded);
    }

    [Fact]
    public void DecodeFromStorage_DecodesEncodedEntities()
    {
        const string encoded = "Tom &amp; Jerry &lt;b&gt;bold&lt;/b&gt; &amp;nbsp;";

        var decoded = InputEncodingService.DecodeFromStorage(encoded);

        Assert.Equal("Tom & Jerry <b>bold</b> &nbsp;", decoded);
    }
}

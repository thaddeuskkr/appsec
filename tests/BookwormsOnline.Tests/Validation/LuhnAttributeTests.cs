using System.ComponentModel.DataAnnotations;
using BookwormsOnline.Validation;

namespace BookwormsOnline.Tests.Validation;

public class LuhnAttributeTests
{
    private readonly LuhnAttribute _attribute = new();

    [Fact]
    public void ValidCard_PassesValidation()
    {
        var context = new ValidationContext(new object());
        var result = _attribute.GetValidationResult("4111111111111111", context);

        Assert.Equal(ValidationResult.Success, result);
    }

    [Fact]
    public void InvalidCard_FailsValidation()
    {
        var context = new ValidationContext(new object());
        var result = _attribute.GetValidationResult("4111111111111112", context);

        Assert.NotEqual(ValidationResult.Success, result);
    }
}

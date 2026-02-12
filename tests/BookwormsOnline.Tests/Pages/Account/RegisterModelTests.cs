using BookwormsOnline.Options;
using BookwormsOnline.Pages.Account;
using BookwormsOnline.Services;
using BookwormsOnline.Tests.TestHelpers;
using Microsoft.Extensions.Options;
using Moq;

namespace BookwormsOnline.Tests.Pages.Account;

public class RegisterModelTests
{
    [Fact]
    public void PasswordPolicyFlags_AreExposedToView()
    {
        var policy = new SecurityPolicyOptions
        {
            PasswordMinLength = 16,
            RequireUppercase = false,
            RequireLowercase = true,
            RequireDigit = false,
            RequireSpecial = true
        };

        var model = new RegisterModel(
            IdentityMocks.CreateUserManagerMock().Object,
            Mock.Of<IFieldEncryptionService>(),
            Mock.Of<IPhotoStorageService>(),
            Mock.Of<IRecaptchaService>(),
            Mock.Of<IAuditLogService>(),
            Mock.Of<IPasswordPolicyService>(),
            Mock.Of<IEmailSender>(),
            Microsoft.Extensions.Options.Options.Create(policy),
            Microsoft.Extensions.Options.Options.Create(new RecaptchaOptions
            {
                SiteKey = "site-key",
                SecretKey = "secret-key"
            }));

        Assert.Equal(16, model.PasswordMinLength);
        Assert.False(model.RequireUppercase);
        Assert.True(model.RequireLowercase);
        Assert.False(model.RequireDigit);
        Assert.True(model.RequireSpecial);
    }
}

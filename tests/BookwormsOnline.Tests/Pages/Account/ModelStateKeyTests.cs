using System.Security.Claims;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Pages.Account;
using BookwormsOnline.Services;
using BookwormsOnline.Tests.TestHelpers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Moq;

namespace BookwormsOnline.Tests.Pages.Account;

public class ModelStateKeyTests
{
    [Fact]
    public async Task ChangePassword_UsesInputNewPasswordKey_WhenPasswordIsReused()
    {
        var user = new ApplicationUser
        {
            Id = "user-1",
            UserName = "member@example.com",
            Email = "member@example.com"
        };

        var userManager = IdentityMocks.CreateUserManagerMock();
        userManager
            .Setup(x => x.GetUserAsync(It.IsAny<ClaimsPrincipal>()))
            .ReturnsAsync(user);

        var passwordPolicy = new Mock<IPasswordPolicyService>();
        passwordPolicy.Setup(x => x.IsPasswordExpired(user)).Returns(false);

        var remaining = TimeSpan.Zero;
        passwordPolicy.Setup(x => x.CanChangePassword(user, out remaining)).Returns(true);
        passwordPolicy
            .Setup(x => x.IsPasswordReusedAsync(user, "NewPassword@123", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var model = new ChangePasswordModel(
            userManager.Object,
            IdentityMocks.CreateSignInManagerMock(userManager.Object).Object,
            passwordPolicy.Object,
            Mock.Of<IAuditLogService>(),
            Microsoft.Extensions.Options.Options.Create(new SecurityPolicyOptions()));

        model.PageContext = new PageContext { HttpContext = new DefaultHttpContext() };
        model.Input = new ChangePasswordModel.InputModel
        {
            CurrentPassword = "CurrentPassword@123",
            NewPassword = "NewPassword@123",
            ConfirmPassword = "NewPassword@123"
        };

        var result = await model.OnPostAsync();

        Assert.IsType<PageResult>(result);
        Assert.True(model.ModelState.ContainsKey("Input.NewPassword"));
        Assert.Contains(
            model.ModelState["Input.NewPassword"]!.Errors,
            error => error.ErrorMessage.Contains("recent passwords", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ResetPassword_UsesInputPasswordKey_AndTrimsEmail_WhenPasswordIsReused()
    {
        var user = new ApplicationUser
        {
            Id = "user-2",
            UserName = "member@example.com",
            Email = "member@example.com"
        };

        var userManager = IdentityMocks.CreateUserManagerMock();
        userManager.Setup(x => x.FindByEmailAsync("member@example.com")).ReturnsAsync(user);

        var passwordPolicy = new Mock<IPasswordPolicyService>();
        passwordPolicy
            .Setup(x => x.IsPasswordReusedAsync(user, "ResetPassword@123", It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var model = new ResetPasswordModel(
            userManager.Object,
            passwordPolicy.Object,
            Mock.Of<IAuditLogService>(),
            Microsoft.Extensions.Options.Options.Create(new SecurityPolicyOptions()))
        {
            Input = new ResetPasswordModel.InputModel
            {
                Email = "  member@example.com  ",
                Password = "ResetPassword@123",
                ConfirmPassword = "ResetPassword@123",
                Code = "encoded-token"
            }
        };

        var result = await model.OnPostAsync();

        Assert.IsType<PageResult>(result);
        Assert.Equal("member@example.com", model.Input.Email);
        Assert.True(model.ModelState.ContainsKey("Input.Password"));
        Assert.Contains(
            model.ModelState["Input.Password"]!.Errors,
            error => error.ErrorMessage.Contains("recent passwords", StringComparison.OrdinalIgnoreCase));
    }
}

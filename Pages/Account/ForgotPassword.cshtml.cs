using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using System.Text;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class ForgotPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailSender _emailSender;
    private readonly IAuditLogService _auditLogService;
    private readonly IAppUrlService _appUrlService;

    public ForgotPasswordModel(
        UserManager<ApplicationUser> userManager,
        IEmailSender emailSender,
        IAuditLogService auditLogService,
        IAppUrlService appUrlService)
    {
        _userManager = userManager;
        _emailSender = emailSender;
        _auditLogService = auditLogService;
        _appUrlService = appUrlService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool EmailSent { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        Input.Email = NormalizeEmail(Input.Email);

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user is not null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var callbackUrl = _appUrlService.BuildPageUrl(
                "/Account/ResetPassword",
                new { code = encodedToken, email = user.Email });

            await _emailSender.SendAsync(
                user.Email!,
                "Bookworms password reset",
                $"<p>Reset your password by <a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clicking here</a>.</p>",
                cancellationToken);
        }

        await _auditLogService.LogAsync("ForgotPassword", "Requested", details: "Password reset request submitted.", cancellationToken: cancellationToken);
        EmailSent = true;
        return Page();
    }

    private static string NormalizeEmail(string email)
    {
        return email.Trim();
    }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;
    }
}

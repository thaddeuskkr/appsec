using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace BookwormsOnline.Pages.Account;

[AllowAnonymous]
public class ResendConfirmationModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailSender _emailSender;
    private readonly IAuditLogService _auditLogService;
    private readonly IAppUrlService _appUrlService;

    public ResendConfirmationModel(
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

    public void OnGet(string? email = null)
    {
        if (!string.IsNullOrWhiteSpace(email))
        {
            Input.Email = email.Trim();
        }
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        Input.Email = NormalizeEmail(Input.Email);

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        if (user is not null && !user.EmailConfirmed)
        {
            var sent = await SendConfirmationEmailAsync(user, cancellationToken);
            if (!sent)
            {
                ModelState.AddModelError(string.Empty, "Unable to send confirmation email right now. Please try again.");
                return Page();
            }
        }
        else
        {
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "ResendRequested",
                user?.Id,
                user is null ? "Resend requested for unknown email." : "Resend requested for already confirmed email.",
                cancellationToken);
        }

        EmailSent = true;
        return Page();
    }

    private async Task<bool> SendConfirmationEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
        var callbackUrl = _appUrlService.BuildPageUrl(
            "/Account/ConfirmEmail",
            new { userId = user.Id, code = encodedToken });

        try
        {
            await _emailSender.SendAsync(
                user.Email!,
                "Confirm your Bookworms Online account",
                $"<p>Please confirm your email by <a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clicking this link</a>.</p>",
                cancellationToken);
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "Resent",
                user.Id,
                "Confirmation email resent.",
                cancellationToken);
            return true;
        }
        catch (Exception exception)
        {
            await _auditLogService.LogAsync(
                "EmailConfirmation",
                "Failed",
                user.Id,
                $"Confirmation email resend failed. {exception.GetType().Name}",
                cancellationToken);
            return false;
        }
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

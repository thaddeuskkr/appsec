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
public class ConfirmEmailModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogService _auditLogService;

    public ConfirmEmailModel(UserManager<ApplicationUser> userManager, IAuditLogService auditLogService)
    {
        _userManager = userManager;
        _auditLogService = auditLogService;
    }

    public bool IsSuccess { get; private set; }

    public string Message { get; private set; } = "We could not verify your email with that link.";

    public string? Email { get; private set; }

    public async Task<IActionResult> OnGetAsync(string? userId = null, string? code = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(code))
        {
            await _auditLogService.LogAsync("EmailConfirmation", "Failed", details: "Missing userId or code in confirmation request.", cancellationToken: cancellationToken);
            Message = "Invalid confirmation link.";
            return Page();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            await _auditLogService.LogAsync("EmailConfirmation", "Failed", details: "Unknown user in confirmation request.", cancellationToken: cancellationToken);
            Message = "Invalid confirmation link.";
            return Page();
        }

        Email = user.Email;

        string token;
        try
        {
            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        }
        catch (FormatException)
        {
            await _auditLogService.LogAsync("EmailConfirmation", "Failed", user.Id, "Malformed confirmation token.", cancellationToken);
            Message = "Invalid confirmation token.";
            return Page();
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (result.Succeeded)
        {
            IsSuccess = true;
            Message = "Your email has been confirmed. You can sign in now.";
            await _auditLogService.LogAsync("EmailConfirmation", "Succeeded", user.Id, "Email confirmation completed.", cancellationToken);
            return Page();
        }

        if (await _userManager.IsEmailConfirmedAsync(user))
        {
            IsSuccess = true;
            Message = "Your email is already confirmed. You can sign in.";
            await _auditLogService.LogAsync("EmailConfirmation", "AlreadyConfirmed", user.Id, "Already-confirmed email visited confirmation endpoint.", cancellationToken);
            return Page();
        }

        await _auditLogService.LogAsync("EmailConfirmation", "Failed", user.Id, "Email confirmation token rejected.", cancellationToken);
        Message = "Confirmation link is invalid or expired. Request a new confirmation email.";
        return Page();
    }
}

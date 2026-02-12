using System.ComponentModel.DataAnnotations;
using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages.Account;

[Authorize]
public class TwoFactorModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogService _auditLogService;

    public TwoFactorModel(UserManager<ApplicationUser> userManager, IAuditLogService auditLogService)
    {
        _userManager = userManager;
        _auditLogService = auditLogService;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public async Task<IActionResult> OnGetAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Account/Login");
        }

        Input.EnableTwoFactor = user.TwoFactorEnabled;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return RedirectToPage("/Account/Login");
        }

        var result = await _userManager.SetTwoFactorEnabledAsync(user, Input.EnableTwoFactor);
        if (!result.Succeeded)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            await _auditLogService.LogAsync(
                "TwoFactorSettings",
                "Failed",
                user.Id,
                $"Could not update 2FA setting. Requested={Input.EnableTwoFactor}",
                cancellationToken);
            return Page();
        }

        await _auditLogService.LogAsync(
            "TwoFactorSettings",
            "Succeeded",
            user.Id,
            $"2FA updated. Enabled={Input.EnableTwoFactor}",
            cancellationToken);

        TempData["StatusMessage"] = Input.EnableTwoFactor
            ? "Two-factor authentication is now enabled."
            : "Two-factor authentication is now disabled.";
        return RedirectToPage("/Account/TwoFactor");
    }

    public class InputModel
    {
        [Display(Name = "Require one-time code (email OTP) at login")]
        public bool EnableTwoFactor { get; set; }
    }
}

using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages.Account;

[Authorize]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditLogService _auditLogService;
    private readonly IActiveSessionService _activeSessionService;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IAuditLogService auditLogService,
        IActiveSessionService activeSessionService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditLogService = auditLogService;
        _activeSessionService = activeSessionService;
    }

    public IActionResult OnGet()
    {
        return RedirectToPage("/Index");
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken = default)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is not null)
        {
            if (!string.IsNullOrWhiteSpace(user.CurrentSessionToken))
            {
                await _activeSessionService.EndSessionAsync(user.CurrentSessionToken, cancellationToken);
            }

            user.CurrentSessionToken = null;
            await _userManager.UpdateAsync(user);
            await _auditLogService.LogAsync("Logout", "Succeeded", user.Id, "User logged out.", cancellationToken);
        }

        await _signInManager.SignOutAsync();
        return RedirectToPage("/Account/Login");
    }
}

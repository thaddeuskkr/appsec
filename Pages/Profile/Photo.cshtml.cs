using BookwormsOnline.Models;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace BookwormsOnline.Pages.Profile;

[Authorize]
public class PhotoModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IPhotoStorageService _photoStorageService;

    public PhotoModel(UserManager<ApplicationUser> userManager, IPhotoStorageService photoStorageService)
    {
        _userManager = userManager;
        _photoStorageService = photoStorageService;
    }

    public async Task<IActionResult> OnGetAsync(string userId, CancellationToken cancellationToken = default)
    {
        var currentUserId = _userManager.GetUserId(User);
        if (string.IsNullOrWhiteSpace(currentUserId) || !string.Equals(currentUserId, userId, StringComparison.Ordinal))
        {
            return Forbid();
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null || string.IsNullOrWhiteSpace(user.PhotoFileName))
        {
            return NotFound();
        }

        var fileStream = await _photoStorageService.OpenReadAsync(user.PhotoFileName, cancellationToken);
        if (fileStream is null)
        {
            return NotFound();
        }

        var contentType = GetImageContentType(user.PhotoFileName);
        if (contentType is null)
        {
            return NotFound();
        }

        return File(fileStream, contentType);
    }

    private static string? GetImageContentType(string fileName)
    {
        var extension = Path.GetExtension(fileName);
        if (string.Equals(extension, ".jpg", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(extension, ".jpeg", StringComparison.OrdinalIgnoreCase))
        {
            return "image/jpeg";
        }

        return null;
    }
}

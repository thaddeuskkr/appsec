using System.Security.Claims;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class ApplicationUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>
{
    public ApplicationUserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, roleManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var identity = await base.GenerateClaimsAsync(user);

        if (!string.IsNullOrWhiteSpace(user.CurrentSessionToken))
        {
            identity.AddClaim(new Claim(SecurityClaimTypes.SessionToken, user.CurrentSessionToken));
        }

        identity.AddClaim(new Claim(ClaimTypes.GivenName, InputEncodingService.DecodeFromStorage(user.FirstName)));
        identity.AddClaim(new Claim(ClaimTypes.Surname, InputEncodingService.DecodeFromStorage(user.LastName)));

        return identity;
    }
}

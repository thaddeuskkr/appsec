using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Options;

public class SecurityPolicyOptions
{
    [Range(8, 128)]
    public int PasswordMinLength { get; set; } = 12;

    public bool RequireUppercase { get; set; } = true;

    public bool RequireLowercase { get; set; } = true;

    public bool RequireDigit { get; set; } = true;

    public bool RequireSpecial { get; set; } = true;

    [Range(1, 24)]
    public int PasswordHistoryCount { get; set; } = 2;

    [Range(0, 1440)]
    public int PasswordMinAgeMinutes { get; set; } = 5;

    [Range(1, 3650)]
    public int PasswordMaxAgeDays { get; set; } = 90;

    [Range(1, 20)]
    public int LockoutMaxFailedAttempts { get; set; } = 3;

    [Range(1, 1440)]
    public int LockoutMinutes { get; set; } = 15;

    [Range(1, 1440)]
    public int SessionIdleTimeoutMinutes { get; set; } = 15;

    public bool SingleActiveSession { get; set; } = true;

    [Range(1, 1440)]
    public int AutoUnlockMinutes { get; set; } = 15;

    public bool EnableHttpsRedirectionInDevelopment { get; set; }
}

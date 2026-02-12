using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Options;

public class RecaptchaOptions
{
    [Required]
    public string SiteKey { get; set; } = string.Empty;

    [Required]
    public string SecretKey { get; set; } = string.Empty;

    [Range(0.0, 1.0)]
    public double MinScore { get; set; } = 0.5;

    [Required]
    public string VerifyEndpoint { get; set; } = "https://www.google.com/recaptcha/api/siteverify";
}

using System.Security.Claims;
using BookwormsOnline.Data;
using BookwormsOnline.Models;
using BookwormsOnline.Options;
using BookwormsOnline.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddOptions<SecurityPolicyOptions>()
    .Bind(configuration.GetSection("SecurityPolicy"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<RecaptchaOptions>()
    .Bind(configuration.GetSection("Recaptcha"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<SmtpOptions>()
    .Bind(configuration.GetSection("Smtp"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<AppUrlOptions>()
    .Bind(configuration.GetSection("AppUrl"))
    .ValidateDataAnnotations()
    .Validate(x => Uri.TryCreate(x.PublicBaseUrl, UriKind.Absolute, out _), "AppUrl:PublicBaseUrl must be an absolute URL.")
    .ValidateOnStart();

builder.Services.AddOptions<StorageOptions>()
    .Bind(configuration.GetSection("Storage"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

var policyOptions = configuration.GetSection("SecurityPolicy").Get<SecurityPolicyOptions>() ?? new SecurityPolicyOptions();
var storageOptions = configuration.GetSection("Storage").Get<StorageOptions>() ?? new StorageOptions();

var contentRoot = builder.Environment.ContentRootPath;
var dataProtectionPath = Path.IsPathRooted(storageOptions.DataProtectionKeysPath)
    ? storageOptions.DataProtectionKeysPath
    : Path.Combine(contentRoot, storageOptions.DataProtectionKeysPath);

Directory.CreateDirectory(dataProtectionPath);

builder.Services.AddDataProtection()
    .SetApplicationName("BookwormsOnline")
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionPath));

var connectionString = configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' is required.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(
        connectionString,
        new MariaDbServerVersion(new Version(10, 11, 0)),
        mySqlOptions => mySqlOptions.EnableRetryOnFailure(5, TimeSpan.FromSeconds(10), null)));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;

        options.Password.RequiredLength = policyOptions.PasswordMinLength;
        options.Password.RequireUppercase = policyOptions.RequireUppercase;
        options.Password.RequireLowercase = policyOptions.RequireLowercase;
        options.Password.RequireDigit = policyOptions.RequireDigit;
        options.Password.RequireNonAlphanumeric = policyOptions.RequireSpecial;
        options.Password.RequiredUniqueChars = 1;

        options.Lockout.MaxFailedAccessAttempts = policyOptions.LockoutMaxFailedAttempts;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(policyOptions.LockoutMinutes);
        options.Lockout.AllowedForNewUsers = true;

        options.SignIn.RequireConfirmedAccount = true;
        options.SignIn.RequireConfirmedEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "BookwormsOnline.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Errors/403";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(policyOptions.SessionIdleTimeoutMinutes);
    options.SlidingExpiration = true;
    options.Events.OnValidatePrincipal = ValidateSessionPrincipalAsync;
});

if (builder.Environment.IsDevelopment())
{
    builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme, options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

    builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ExternalScheme, options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

    builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme, options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });

    builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorRememberMeScheme, options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });
}

builder.Services.AddHttpContextAccessor();
builder.Services.AddRazorPages()
    .AddMvcOptions(options => { options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()); });

builder.Services.AddHttpClient<IRecaptchaService, RecaptchaService>();
builder.Services.AddScoped<IFieldEncryptionService, FieldEncryptionService>();
builder.Services.AddScoped<IPhotoStorageService, PhotoStorageService>();
builder.Services.AddScoped<IAuditLogService, AuditLogService>();
builder.Services.AddScoped<IPasswordPolicyService, PasswordPolicyService>();
builder.Services.AddScoped<IEmailSender, SmtpEmailSender>();
builder.Services.AddScoped<IActiveSessionService, ActiveSessionService>();
builder.Services.AddSingleton<IAppUrlService, AppUrlService>();
builder.Services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, ApplicationUserClaimsPrincipalFactory>();

var app = builder.Build();

app.UseExceptionHandler("/Errors/500");
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/Errors/{0}");
if (!app.Environment.IsDevelopment() || policyOptions.EnableHttpsRedirectionInDevelopment)
{
    app.UseHttpsRedirection();
}
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["X-XSS-Protection"] = "0";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; " +
        "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; " +
        "img-src 'self' data:; " +
        "frame-src https://www.google.com/recaptcha/; " +
        "connect-src 'self' https://www.google.com/recaptcha/;";

    await next();
});
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
    try
    {
        dbContext.Database.Migrate();
    }
    catch (Exception exception)
    {
        logger.LogWarning(exception, "Database migration could not be applied at startup.");
    }
}

app.Run();

static async Task ValidateSessionPrincipalAsync(CookieValidatePrincipalContext context)
{
    if (context.Principal?.Identity?.IsAuthenticated is not true)
    {
        return;
    }

    var claimToken = context.Principal.FindFirstValue(SecurityClaimTypes.SessionToken);
    if (string.IsNullOrWhiteSpace(claimToken))
    {
        await RejectSessionAsync(context);
        return;
    }

    var activeSessionService = context.HttpContext.RequestServices.GetRequiredService<IActiveSessionService>();
    if (!await activeSessionService.RefreshSessionAsync(claimToken))
    {
        await RejectSessionAsync(context);
        return;
    }

    var policy = context.HttpContext.RequestServices.GetRequiredService<IOptions<SecurityPolicyOptions>>().Value;
    if (!policy.SingleActiveSession)
    {
        return;
    }

    var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
    var user = await userManager.GetUserAsync(context.Principal);
    if (user is null)
    {
        await activeSessionService.EndSessionAsync(claimToken);
        await RejectSessionAsync(context);
        return;
    }

    if (!string.Equals(claimToken, user.CurrentSessionToken, StringComparison.Ordinal))
    {
        await activeSessionService.EndSessionAsync(claimToken);
        await RejectSessionAsync(context);
    }
}

static async Task RejectSessionAsync(CookieValidatePrincipalContext context)
{
    context.RejectPrincipal();
    await context.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
}

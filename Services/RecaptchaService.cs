using System.Net.Http.Json;
using System.Text.Json.Serialization;
using BookwormsOnline.Options;
using Microsoft.Extensions.Options;

namespace BookwormsOnline.Services;

public class RecaptchaService : IRecaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly RecaptchaOptions _options;

    public RecaptchaService(HttpClient httpClient, IOptions<RecaptchaOptions> options)
    {
        _httpClient = httpClient;
        _options = options.Value;
    }

    public async Task<RecaptchaVerificationResult> VerifyAsync(
        string token,
        string expectedAction,
        string? remoteIp,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new RecaptchaVerificationResult(false, 0, "missing-token");
        }

        var formValues = new Dictionary<string, string>
        {
            ["secret"] = _options.SecretKey,
            ["response"] = token
        };

        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            formValues["remoteip"] = remoteIp;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.VerifyEndpoint)
        {
            Content = new FormUrlEncodedContent(formValues)
        };

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return new RecaptchaVerificationResult(false, 0, $"http-{(int)response.StatusCode}");
        }

        var payload = await response.Content.ReadFromJsonAsync<RecaptchaResponse>(cancellationToken: cancellationToken);
        if (payload is null)
        {
            return new RecaptchaVerificationResult(false, 0, "empty-response");
        }

        var actionMatches = string.Equals(payload.Action, expectedAction, StringComparison.OrdinalIgnoreCase);
        var scorePasses = payload.Score >= _options.MinScore;
        var success = payload.Success && actionMatches && scorePasses;

        var error = success ? null : payload.ErrorCodes?.FirstOrDefault() ?? "verification-failed";
        return new RecaptchaVerificationResult(success, payload.Score, error);
    }

    private sealed class RecaptchaResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; init; }

        [JsonPropertyName("score")]
        public double Score { get; init; }

        [JsonPropertyName("action")]
        public string? Action { get; init; }

        [JsonPropertyName("error-codes")]
        public string[]? ErrorCodes { get; init; }
    }
}

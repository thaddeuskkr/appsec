using Microsoft.AspNetCore.DataProtection;

namespace BookwormsOnline.Services;

public class FieldEncryptionService : IFieldEncryptionService
{
    private readonly IDataProtector _protector;

    public FieldEncryptionService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("BookwormsOnline.SensitiveFields.v1");
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrWhiteSpace(plainText))
        {
            return string.Empty;
        }

        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrWhiteSpace(cipherText))
        {
            return string.Empty;
        }

        return _protector.Unprotect(cipherText);
    }
}

namespace BookwormsOnline.Services;

public interface IFieldEncryptionService
{
    string Encrypt(string plainText);

    string Decrypt(string cipherText);
}

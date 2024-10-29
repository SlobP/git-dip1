using System;
using System.ComponentModel;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using static System.Net.Mime.MediaTypeNames;


public class AesEncryption
{
    public static byte[] Encrypt(string plaintext, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            byte[] encryptedBytes;
            using (var msEncrypt = new System.IO.MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                    csEncrypt.Write(plainBytes, 0, plainBytes.Length);
                }
                encryptedBytes = msEncrypt.ToArray();
            }
            return encryptedBytes;
        }
    }
    public static string Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            try
            {
                byte[] decryptedBytes;
                using (var msDecrypt = new System.IO.MemoryStream(ciphertext))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var msPlain = new System.IO.MemoryStream())
                        {
                            csDecrypt.CopyTo(msPlain);
                            decryptedBytes = msPlain.ToArray();
                        }
                    }
                }
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (CryptographicException ex)
            {
                // Handle the CryptographicException
                Console.WriteLine("Decryption failed: " + ex.Message);
                Console.WriteLine("Wrong password");
                // Optionally, return null or an empty string, or rethrow the exception
                return null; // Or throw; depending on your needs
            }
        }
    }
    public static (byte[] key, byte[] iv) key_gen()
    {
        Console.WriteLine("Password:");
        string password = Console.ReadLine();

        var hash = SHA512.HashData(Encoding.UTF8.GetBytes(password));
        var key = hash.Take(32).ToArray();
        var iv = hash.Skip(32).Take(16).ToArray();

        Console.WriteLine("Password: " + password);
        Console.WriteLine("Hash (Base64): " + Convert.ToBase64String(hash));
        Console.WriteLine("Key (Base64): " + Convert.ToBase64String(key));
        Console.WriteLine("IV (Base64): " + Convert.ToBase64String(iv));
        return (key, iv);
    }
}

class Program
{
    private static readonly string botToken = "BotToken"; // Replace with your actual bot token
    private static readonly string apiUrl = $"https://api.telegram.org/bot{botToken}/";

    static async Task Main(string[] args)
    {
        Console.WriteLine("Welcome to the Telegram Bot Console. Type 'exit' to end the program.");

        while (true)
        {
            Console.WriteLine("Choose an action: 'send' to send a message, 'receive' to get updates, or 'exit' to end:");
            string action = Console.ReadLine();

            if (action.ToLower() == "exit")
            {
                Console.WriteLine("Exiting the program. Goodbye!");
                break;
            }
            else if (action.ToLower() == "send")
            {
                Console.Write("Enter chat ID: "); 
                string chatId = Console.ReadLine();
                var (key, iv) = AesEncryption.key_gen(); // Enter Key
                
                Console.Write("Enter message to send: ");
                string message = Console.ReadLine();

                await SendMessageAsync(chatId, message, key, iv);
            }
            else if (action.ToLower() == "receive")
            {
                Console.Write("Enter chat ID: ");
                string chatId = Console.ReadLine();
                var (key, iv) = AesEncryption.key_gen(); // Enter Key
                
                await GetMessagesAsync(key, iv);
            }
            else
            {
                Console.WriteLine("Invalid action. Please type 'send', 'receive', or 'exit'.");
            }
        }
    }

    private static async Task SendMessageAsync(string chatId, string message, byte[] key, byte[] iv)
    {
        using (HttpClient client = new HttpClient())
        {
            byte[] ciphertext = AesEncryption.Encrypt(message, key, iv); 
            string encryptedText = Convert.ToBase64String(ciphertext);
            Console.WriteLine("Encrypted Text: " + encryptedText);

            var url = $"{apiUrl}sendMessage?chat_id={chatId}&text={encryptedText}";

            HttpResponseMessage response = await client.GetAsync(url);
            string result = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Response from SendMessage: {result}");
        }
    }

    private static async Task GetMessagesAsync(byte[] key, byte[] iv)
    {
        using (HttpClient client = new HttpClient())
        {
            var url = $"{apiUrl}getUpdates";

            HttpResponseMessage response = await client.GetAsync(url);
            string result = await response.Content.ReadAsStringAsync();

            // Parse the JSON response
            JObject json = JObject.Parse(result);
            foreach (var update in json["result"])
            {
                // Check if the message, from, and text fields are present
                var message = update["message"];
                if (message?["from"] != null && message["from"]["username"] != null && message["text"] != null)
                {
                    Console.WriteLine("Message from: " + message["from"]["username"]);

                    // Check whether the message is encrypted and in base64 or is it plain text
                    try
                    {
                        string base64String = message["text"].ToString().Replace(" ", "+");
                        byte[] bytes = Convert.FromBase64String(base64String);
                        
                        string decryptedText = AesEncryption.Decrypt(bytes, key, iv);
                        Console.WriteLine("Text: " + decryptedText);
                        Console.WriteLine();
                    }
                    catch (FormatException)
                    { 
                        Console.WriteLine("Text: " + message["text"]);
                        Console.WriteLine();
                    }                    
                }
                else
                {
                    Console.WriteLine("Received a non-message update or message without necessary fields.");
                }
            }
        }
    }
}

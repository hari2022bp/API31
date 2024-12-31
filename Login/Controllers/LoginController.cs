using Login;
using Login.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Numerics;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly LoginDbContext _context;
    private readonly byte[] Key;
    private readonly byte[] IV;

    public UserController(LoginDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
        Key = GenerateKey(_configuration["SecretKey"]);
        IV = new byte[16]; // Initialize IV as needed
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] User userRequest)
    {
        var user = await _context.Users
           .FirstOrDefaultAsync(u => u.UserName == userRequest.UserName && u.Password == userRequest.Password);
        if (user != null)
        {
            var decryptedPassword = DecryptPassword(user.Password);
            if (decryptedPassword.Equals(userRequest.Password))
            {
                return Ok(new { valid = true, message = "Login successful" });
            }
            return Unauthorized(new { valid = false, message = "Invalid credentials. Please check your username and password." });
        }
        return NotFound(new { valid = false, message = "User not found. Please sign up." });
    }

    private byte[] EncryptPassword(string password)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7; // Ensure padding is set
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream())
            {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(password);
                    }
                }
                return ms.ToArray();
            }
        }
    }

    private string DecryptPassword(byte[] encryptedPassword)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = Key;
            aes.IV = IV;
            aes.Padding = PaddingMode.PKCS7; // Ensure padding is set
            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using (var ms = new System.IO.MemoryStream(encryptedPassword))
            {
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (var sr = new StreamReader(cs))
                    {
                        return sr.ReadToEnd();
                    }
                }
            }
        }
    }
   


    private byte[] GenerateKey(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        }
    }
}

using System.ComponentModel.DataAnnotations;

namespace Login.Model
{
    public class User
    {
        [Key]
        public int UserId { get; set; }
        public string UserName { get; set; }
        public byte[] Password { get; set; }
        //public string Password { get; set; }
    }
}

   

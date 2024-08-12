


namespace AutoPartsHub.Models
{
    public class Login
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; } = false;
        public bool isInvalid { get; set; } = false;
        public string InvalidMessage { get; set; } = "";
    }
}



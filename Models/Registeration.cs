namespace AutoPartsHub.Models
{
    public class Registeration
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string PhoneNumber { get; set; }
        //public string ConfirmPassword { get; set; }
        public bool RememberMe { get; set; } = false;

    }
}

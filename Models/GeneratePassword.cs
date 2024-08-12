namespace AutoPartsHub.Models
{
    public class GeneratePassword
    {
        public static string GenerateRandomPassword(int length)
        {
            const string numbers = "0123456789";
            const string letters = "abcdefghijklmnoqprstuvwyzx";
            const string LETTERS = "ABCDEFGHIJKLMNOQPRSTUYWVZX";
            const string symbols = "!@#$^&*?";

            string allChars = numbers + letters + LETTERS + symbols;
            Random random = new Random();
            char[] password = new char[length];

            for (int i = 0; i < length; i++)
            {
                int randomIndex = random.Next(allChars.Length);
                password[i] = allChars[randomIndex];
            }

            return new string(password);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace _Helper
{
    public static class Protection
    {
        public static string Encrypt(string strPlainText)
        {
            if (string.IsNullOrEmpty(strPlainText))
            {
                return "";
            }
            TripleDESCryptoServiceProvider crp = new TripleDESCryptoServiceProvider();
            UnicodeEncoding uEncode = new UnicodeEncoding();
            ASCIIEncoding aEncode = new ASCIIEncoding();
            byte[] bytPlainText = uEncode.GetBytes(strPlainText);
            MemoryStream stmCipherText = new MemoryStream();
            byte[] slt = new byte[0];
            PasswordDeriveBytes pdb = new PasswordDeriveBytes("138714964834954456763246", slt);
            byte[] bytDerivedKey = pdb.GetBytes(24);
            crp.Key = bytDerivedKey;
            crp.IV = pdb.GetBytes(8);
            CryptoStream csEncrypted = new CryptoStream(stmCipherText, crp.CreateEncryptor(), CryptoStreamMode.Write);
            csEncrypted.Write(bytPlainText, 0, bytPlainText.Length);
            csEncrypted.FlushFinalBlock();
            return Convert.ToBase64String(stmCipherText.ToArray());
        }
        public static string Decrypt(string strCipherText)
        {
            if (string.IsNullOrEmpty(strCipherText))
            {
                return "";
            }
            TripleDESCryptoServiceProvider crp = new TripleDESCryptoServiceProvider();
            UnicodeEncoding uEncode = new UnicodeEncoding();
            ASCIIEncoding aEncode = new ASCIIEncoding();
            byte[] bytCipherText = Convert.FromBase64String(strCipherText);
            MemoryStream stmPlainText = new MemoryStream();
            MemoryStream stmCipherText = new MemoryStream(bytCipherText);
            byte[] slt = new byte[0];
            PasswordDeriveBytes pdb = new PasswordDeriveBytes("138714964834954456763246", slt);
            byte[] bytDerivedKey = pdb.GetBytes(24);
            crp.Key = bytDerivedKey;
            crp.IV = pdb.GetBytes(8);
            CryptoStream csDecrypted = new CryptoStream(stmCipherText, crp.CreateDecryptor(), CryptoStreamMode.Read);
            StreamWriter sw = new StreamWriter(stmPlainText);
            StreamReader sr = new StreamReader(csDecrypted);
            sw.Write(sr.ReadToEnd());
            sw.Flush();
            csDecrypted.Clear();
            crp.Clear();
            return uEncode.GetString(stmPlainText.ToArray());
        }

        internal static string CreateRandomPasswordWithRandomLength()
        {
            // Create a string of characters, numbers, special characters that allowed in the password  
            string validChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*?_-";
            Random random = new Random();

            // Minimum size 8. Max size is number of all allowed chars.  
            int size = random.Next(8, 13);

            // Select one random character at a time from the string  
            // and create an array of chars  
            char[] chars = new char[size];
            for (int i = 0; i < size; i++)
            {
                chars[i] = validChars[random.Next(0, validChars.Length)];
            }
            return new string(chars);
        }
    }
}

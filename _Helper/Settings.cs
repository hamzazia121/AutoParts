using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AutoPartsHub._Helper
{
    public class Settings
    {
        public static byte[] ResizePic(IFormFile file, int width, int height)
        {
            var image = Image.FromStream(file.OpenReadStream());
            var resized = new Bitmap(image, new Size(width, height));
            using var imageStream = new MemoryStream();
            resized.Save(imageStream, ImageFormat.Jpeg);
            var imageBytes = imageStream.ToArray();
            return imageBytes;

        }
        //public static Image CreateProfilePicture(string name)
        //{
        //    Font font = new Font(FontFamily.GenericSerif, 45, FontStyle.Bold);
        //    Color fontcolor = ColorTranslator.FromHtml("#FFF");
        //    Color bgcolor = ColorTranslator.FromHtml("#83B869");
        //     var data=GenerateAvtarImage(name, font, fontcolor, bgcolor,name);
        //    return data;
        //}
        //static  Image GenerateAvtarImage(String text, Font font, Color textColor, Color backColor, string filename)
        //{
        //    //first, create a dummy bitmap just to get a graphics object  
        //    Image img = new Bitmap(1, 1);
        //    Graphics drawing = Graphics.FromImage(img);

        //    //measure the string to see how big the image needs to be  
        //    SizeF textSize = drawing.MeasureString(text, font);

        //    //free up the dummy image and old graphics object  
        //    img.Dispose();
        //    drawing.Dispose();

        //    //create a new image of the right size  
        //    img = new Bitmap(110, 110);

        //    drawing = Graphics.FromImage(img);

        //    //paint the background  
        //    drawing.Clear(backColor);

        //    //create a brush for the text  
        //    Brush textBrush = new SolidBrush(textColor);

        //    //drawing.DrawString(text, font, textBrush, 0, 0);  
        //    drawing.DrawString(text, font, textBrush, new Rectangle(-2, 20, 200, 110));

        //    drawing.Save();

        //    textBrush.Dispose();
        //    drawing.Dispose();

           

        //    return img;

        //}
    }
}

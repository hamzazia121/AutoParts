using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;
using Microsoft.CodeAnalysis;
using Microsoft.Extensions.Hosting;
using AutoPartsHub._Helper;
using IHostingEnvironment = Microsoft.AspNetCore.Hosting.IHostingEnvironment;

namespace AutoPartsHub.Controllers
{
    [CustomAuthorization]

    public class ItemImagesController : Controller
    {
        private readonly AutoPartsHubContext _context;
        private readonly IWebHostEnvironment _hostEnvironment;

        public ItemImagesController(AutoPartsHubContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostEnvironment = hostingEnvironment;
        }

        // GET: ItemImages
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = _context.TblItemImages.Where(x => x.MDelete == false || x.MDelete == null).Include(t => t.Item);
            return View(await autoPartsHubContext.ToListAsync());
        }

        // GET: ItemImages/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemImage = await _context.TblItemImages
                .Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ItemImageId == id);
            if (tblItemImage == null)
            {
                return NotFound();
            }

            return View(tblItemImage);
        }

        // GET: ItemImages/Create
        public IActionResult Create()
        {
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            return View();
        }

        // POST: ItemImages/Create
        //To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ItemImageName,ItemName,ItemId")] TblItemImage tblItemImage, IFormFileCollection ImageFiles)
        {
            if (ModelState.IsValid)
            {
                int count = 0;
                foreach (var file in ImageFiles)
                {
                    var newItemImage = new TblItemImage
                    {
                        ItemImageName = tblItemImage.ItemImageName,
                        ItemId = tblItemImage.ItemId,
                        CreatedAt = DateTime.Now,
                        CreatedBy = 1 // Assuming the CreatedBy user ID is 1
                    };

                    if (count == 0)
                    {
                        newItemImage.IsDefault = true;
                    }
                    else
                    {
                        newItemImage.IsDefault = false;
                    }

                    var imagesType = UploadImage(file, newItemImage.ItemId);
                    newItemImage.BanerImage = imagesType.Slider;
                    newItemImage.ThumbnailImage = imagesType.Thumbnail;
                    newItemImage.NormalImage = imagesType.Default;

                    _context.Add(newItemImage);
                    await _context.SaveChangesAsync();
                    count++;
                }





                return RedirectToAction(nameof(Index));
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemImage.ItemId);
            return View(tblItemImage);
        }


        private ImagesType UploadImage(IFormFile file, int itemId)
        {
            var fileName = Path.GetFileName(file.FileName);
            var Image = Guid.NewGuid().ToString() + fileName;

            var fileExtension = Path.GetExtension(fileName);
            string wwwRootPath = _hostEnvironment.WebRootPath;
            string UploadedFolderThub = $"/Uploadimages/ProductImages/{itemId}/Thubnail/";
            string UploadedFolderDefault = $"/Uploadimages/ProductImages/{itemId}/Default/";
            string UploadedFolderSlider = $"/Uploadimages/ProductImages/{itemId}/Slider/";

            var basePaththub = Path.Combine(wwwRootPath + UploadedFolderThub);
            var basePathDefault = Path.Combine(wwwRootPath + UploadedFolderDefault);
            var basePathSlider = Path.Combine(wwwRootPath + UploadedFolderSlider);

            bool basePathThubExists = System.IO.Directory.Exists(basePaththub);
            bool basePathDefaultExists = System.IO.Directory.Exists(UploadedFolderDefault);
            bool basePathSliderExists = System.IO.Directory.Exists(UploadedFolderSlider);

            if (!basePathThubExists) Directory.CreateDirectory(basePaththub);
            if (!basePathDefaultExists) Directory.CreateDirectory(basePathDefault);
            if (!basePathSliderExists) Directory.CreateDirectory(basePathSlider);


            var imageBytesThumb = Settings.ResizePic(file, 109, 122);


            var filePaththub = Path.Combine(basePaththub, Image);
            using (var stream = new FileStream(filePaththub, FileMode.Create))
            {
                stream.Write(imageBytesThumb, 0, imageBytesThumb.Length);
            }

            var imageBytesDefault = Settings.ResizePic(file, 280, 316);

            var filePathDefault = Path.Combine(basePathDefault, Image);
            using (var stream = new FileStream(filePathDefault, FileMode.Create))
            {
                stream.Write(imageBytesDefault, 0, imageBytesDefault.Length);
            }
            var imageBytesSlider = Settings.ResizePic(file, 800, 900);
            var filePathSlider = Path.Combine(basePathSlider, Image);
            using (var stream = new FileStream(filePathSlider, FileMode.Create))
            {
                stream.Write(imageBytesSlider, 0, imageBytesSlider.Length);
            }

            var imagesType = new ImagesType
            {
                Default = UploadedFolderDefault + Image,
                Thumbnail = UploadedFolderThub + Image,
                Slider = UploadedFolderSlider + Image
            };
            //string imageURL =  UploadedFolder + Image;

            return imagesType;


        }

        private async Task<string> SaveFiles(IFormFile[] files, int itemImageId, string folderType, int width, int height)
        {
            string wwwRootPath = _hostEnvironment.WebRootPath;
            string folderPath = $"/Uploads/ProductImages/{itemImageId}/{folderType}/";
            string basePath = Path.Combine(wwwRootPath + folderPath);

            if (!Directory.Exists(basePath))
            {
                Directory.CreateDirectory(basePath);
            }

            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file.FileName);
                var Image = Guid.NewGuid().ToString() + fileName;

                var filePath = Path.Combine(basePath, Image);
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var imageBytes = Settings.ResizePic(file, width, height);
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    stream.Write(imageBytes, 0, imageBytes.Length);
                }

                return ".." + folderPath + Image;
            }

            return null;
        }


        // GET: ItemImages/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemImage = await _context.TblItemImages.FindAsync(id);
            if (tblItemImage == null)
            {
                return NotFound();
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemImage.ItemId);
            return View(tblItemImage);
        }

        // POST: ItemImages/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemImageId,ItemImageName,ItemName,ThumbailImage,NormalImage,IsDefault,ItemId,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete,BanerImage")] TblItemImage tblItemImage)
        {
            if (id != tblItemImage.ItemImageId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblItemImage);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemImageExists(tblItemImage.ItemImageId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemImage.ItemId);
            return View(tblItemImage);
        }

        // GET: ItemImages/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemImage = await _context.TblItemImages
                .Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ItemImageId == id);
            if (tblItemImage == null)
            {
                return NotFound();
            }

            return View(tblItemImage);
        }

        // POST: ItemImages/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblItemImage = await _context.TblItemImages.FindAsync(id);
            if (tblItemImage != null)
            {
                tblItemImage.MDelete = true;
                _context.TblItemImages.Update(tblItemImage);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        public async Task<IActionResult> ChangeItemImageTypeAsync(int id)
        {
            try
            {
                if (id == 0) // Checking if id is valid
                {
                    return NotFound();
                }

                // Assuming id here is the specific item's id that needs to be set to IsDefault = true
                var tblItemImage = await _context.TblItemImages.FindAsync(id);
                if (tblItemImage == null)
                {
                    return NotFound();
                }

                // Get the ItemId of the specific item to update other entries with the same ItemId
                int itemId = tblItemImage.ItemId;

                // Retrieve all items with the specified ItemId and set IsDefault to false
                var items = await _context.TblItemImages
                           .Where(item => item.ItemId == itemId ) // Exclude the specific item to be set as default
                           .ToListAsync();

                // Update IsDefault to false for all retrieved items
                foreach (var item in items)
                {
                    item.IsDefault = false;
                    _context.Update(item);
                }

                // Set the specific item as IsDefault = true
                tblItemImage.IsDefault = true;
                _context.Update(tblItemImage);

                // Save changes to the database
                await _context.SaveChangesAsync();

                return Json(new { success = true });
            }
            catch (Exception exp)
            {
                return Json(new { responseText = exp.Message, success = false });
            }
        }

        private bool TblItemImageExists(int id)
        {
            return _context.TblItemImages.Any(e => e.ItemImageId == id);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;
using Microsoft.Extensions.Hosting;
using AutoPartsHub._Helper;
using Microsoft.AspNetCore.Authorization;

namespace AutoPartsHub.Controllers
{
    [CustomAuthorization]
    [Authorize(Roles = "Admin")]

    public class ItemsController : Controller
    {
        private readonly AutoPartsHubContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;

        public ItemsController(AutoPartsHubContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;
        }

        // GET: Items
        public async Task<IActionResult> Index()
        {
            var items = await _context.TblItems
                                      .Where(x => x.MDelete == false || x.MDelete == null)
                                      .Include(t => t.Brand).Include(t => t.TblItemImages)
                                      .ToListAsync();
            return View(items);
        }

        // GET: Items/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var item = await _context.TblItems
                                     .Include(t => t.Brand)
                                     .FirstOrDefaultAsync(m => m.ItemId == id);
            if (item == null)
            {
                return NotFound();
            }

            return View(item);
        }

        // GET: Items/Create
        public IActionResult Create()
        {
            ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName");
            return View();
        }

        // POST: Items/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ItemName,ItemPrice,Discount,IsFeature,BrandId,Sku,DefaultImageUrl,ShortDescription,LongDescription,MDelete")] TblItem tblItem, IFormFileCollection ImageFiles)
        {
            if (ModelState.IsValid)
            { 
                tblItem.ItemSlugs = $"{tblItem.ItemName.Replace(" ", "_")}_{Guid.NewGuid()}";
               
                _context.Add(tblItem);
                await _context.SaveChangesAsync();
               int itemId=tblItem.ItemId;
                var count = 0;
                foreach (var file in ImageFiles)
                {
                    var newItemImage = new TblItemImage
                    {
                        ItemImageName = file.FileName,
                        ItemId =itemId,
                        CreatedAt = DateTime.Now,
                        CreatedBy = 1,
                        MDelete = false
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
            ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName", tblItem.BrandId);
            return View(tblItem);
        }


        private ImagesType UploadImage(IFormFile file, int itemId)
        {
            var fileName = Path.GetFileName(file.FileName);
            var Image = Guid.NewGuid().ToString() + fileName;

            var fileExtension = Path.GetExtension(fileName);
            string wwwRootPath = _hostingEnvironment.WebRootPath;
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
            //string imageURL = UploadedFolder + Image;

            return imagesType;


        }




        // GET: Items/Edit/5
        public async Task<IActionResult> ProductImages(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var item = await _context.TblItems.Include(x=>x.TblItemImages).Include(x=>x.Brand).Include(x=>x.TblItemCategories).FirstOrDefaultAsync(x=>x.ItemId==id);
            if (item == null)
            {
                return NotFound();
            }
            return View(item);
        }

        //// GET: Items/Edit/5
        //public async Task<IActionResult> Edit(int? id)
        //{
        //    if (id == null)
        //    {
        //        return NotFound();
        //    }

        //    var item = await _context.TblItems.FindAsync(id);
        //    if (item == null)
        //    {
        //        return NotFound();
        //    }
        //    ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName", item.BrandId);
        //    return View(item);
        //}


        //// POST: Items/Edit/5
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> Edit(int id, [Bind("ItemId,DefaultImageFile,ItemSlugs,ItemName,ItemPrice,Discount,IsFeature,BrandId,Sku,DefaultImageUrl,ShortDescription,LongDescription,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItem tblItem , IFormFileCollection ImageFiles)
        //{
        //    if (id != tblItem.ItemId)
        //    {
        //        return NotFound();
        //    }

        //    if (ModelState.IsValid)
        //    {
        //        try
        //        {

        //                tblItem.ItemSlugs = $"{tblItem.ItemName.Replace(" ", "_")}_{Guid.NewGuid()}";

        //                _context.Add(tblItem);
        //                await _context.SaveChangesAsync();
        //                int itemId = tblItem.ItemId;
        //                var count = 0;
        //                foreach (var file in ImageFiles)
        //                {
        //                    var newItemImage = new TblItemImage
        //                    {
        //                        ItemImageName = file.FileName,
        //                        ItemId = itemId,
        //                        CreatedAt = DateTime.Now,
        //                        CreatedBy = 1,
        //                        MDelete = false
        //                    };

        //                    if (count == 0)
        //                    {
        //                        newItemImage.IsDefault = true;
        //                    }
        //                    else
        //                    {
        //                        newItemImage.IsDefault = false;
        //                    }

        //                    var imagesType = UploadImage(file, newItemImage.ItemId);
        //                    newItemImage.BanerImage = imagesType.Slider;
        //                    newItemImage.ThumbnailImage = imagesType.Thumbnail;
        //                    newItemImage.NormalImage = imagesType.Default;

        //                    _context.Add(newItemImage);
        //                    await _context.SaveChangesAsync();
        //                    count++;
        //                }

        //                return RedirectToAction(nameof(Index));

        //        }
        //        catch (DbUpdateConcurrencyException)
        //        {
        //            if (!TblItemExists(tblItem.ItemId))
        //            {
        //                return NotFound();
        //            }
        //            else
        //            {
        //                throw;
        //            }
        //        }

        //    }
        //    ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName", tblItem.BrandId);
        //    return View(tblItem);
        //}



        // GET: Items/Edit/5
        [HttpGet("Items/Edit/{id:int}")]
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var item = await _context.TblItems.FindAsync(id);
            if (item == null)
            {
                return NotFound();
            }
            ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName", item.BrandId);
            return View(item);
        }

        // POST: Items/Edit/5
        [HttpPost("Items/Edit/{id:int}")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemId,DefaultImageFile,ItemSlugs,ItemName,ItemPrice,Discount,IsFeature,BrandId,Sku,DefaultImageUrl,ShortDescription,LongDescription,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItem tblItem, IFormFileCollection ImageFiles)
        {
            if (id != tblItem.ItemId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    tblItem.ItemSlugs = $"{tblItem.ItemName.Replace(" ", "_")}_{Guid.NewGuid()}";
                    _context.Update(tblItem);
                    await _context.SaveChangesAsync();

                    // Retrieve existing images
                    var existingImages = _context.TblItemImages.Where(i => i.ItemId == id).ToList();

                    // Delete existing images from the database and file system
                    foreach (var existingImage in existingImages)
                    {
                        _context.TblItemImages.Remove(existingImage);

                        var wwwRootPath = _hostingEnvironment.WebRootPath;
                        var imagePaths = new[]
                        {
                    Path.Combine(wwwRootPath, existingImage.BanerImage),
                    Path.Combine(wwwRootPath, existingImage.ThumbnailImage),
                    Path.Combine(wwwRootPath, existingImage.NormalImage)
                };

                        foreach (var path in imagePaths)
                        {
                            if (System.IO.File.Exists(path))
                            {
                                System.IO.File.Delete(path);
                            }
                        }
                    }

                    await _context.SaveChangesAsync();

                    // Add new images
                    int itemId = tblItem.ItemId;
                    var count = 0;

                    foreach (var file in ImageFiles)
                    {
                        var newItemImage = new TblItemImage
                        {
                            ItemImageName = file.FileName,
                            ItemId = itemId,
                            CreatedAt = DateTime.Now,
                            CreatedBy = 1,
                            MDelete = false
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
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemExists(tblItem.ItemId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
            }
            ViewData["BrandId"] = new SelectList(_context.TblBrands, "BrandId", "BrandName", tblItem.BrandId);
            return View(tblItem);
        }
        // GET: Items/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var item = await _context.TblItems
                                     .Include(t => t.Brand)
                                     .FirstOrDefaultAsync(m => m.ItemId == id);
            if (item == null)
            {
                return NotFound();
            }

            return View(item);
        }

        // POST: Items/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var item = await _context.TblItems.FindAsync(id);
            if (item != null)
            {
                item.MDelete = true;
                _context.TblItems.Update(item);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblItemExists(int id)
        {
            return _context.TblItems.Any(e => e.ItemId == id);
        }

      
    }
}

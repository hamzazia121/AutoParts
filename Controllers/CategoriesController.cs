using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;
using Microsoft.AspNetCore.Authorization;

namespace AutoPartsHub.Controllers
{

    [CustomAuthorization]
    [Authorize(Roles = "Admin")]
    public class CategoriesController : Controller
    {
        private readonly AutoPartsHubContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
      

        public CategoriesController(AutoPartsHubContext context, IWebHostEnvironment webHostingEnvironment)
        {
            _context = context;
            _webHostEnvironment = webHostingEnvironment;
        }

        // GET: Categories
        public async Task<IActionResult> Index()
        {
            var category = await _context.TblCategories.Where(x => x.MDelete==false || x.MDelete==null).ToListAsync();
            return View( category);
        }

        // GET: Categories/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblCategory = await _context.TblCategories
                .FirstOrDefaultAsync(m => m.CategoryId == id);
            if (tblCategory == null)
            {
                return NotFound();
            }

            return View(tblCategory);
        }

        // GET: Categories/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Categories/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("CategoryId,CategoryImageFile,CategoryName,CategoryTitle,CategoryDescription,CategoryImage,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblCategory tblCategory)
        {
            if (ModelState.IsValid)
            {
                if (tblCategory.CategoryImageFile != null)
                {

                    var fileName = Path.GetFileNameWithoutExtension(tblCategory.CategoryImageFile.FileName);
                    var fileExtension = Path.GetExtension(tblCategory.CategoryImageFile.FileName);
                    var Image = $"{fileName}_{Guid.NewGuid().ToString()}.{fileExtension}";

                    string wwwRootPath = _webHostEnvironment.WebRootPath;
                    string UploadedFolder = $"/Uploadimages/BrandImages/";




                    var basePath = Path.Combine(wwwRootPath + UploadedFolder);



                    bool basePathExists = System.IO.Directory.Exists(basePath);



                    if (!basePathExists) Directory.CreateDirectory(basePath);



                    var filePath = Path.Combine(basePath, Image);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        tblCategory.CategoryImageFile.CopyTo(stream);


                    }

                    string imageURL = UploadedFolder + Image;
                    tblCategory.CategoryImage = imageURL;
                }
                _context.Add(tblCategory);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblCategory);
        }

        // GET: Categories/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblCategory = await _context.TblCategories.FindAsync(id);
            if (tblCategory == null)
            {
                return NotFound();
            }
            return View(tblCategory);
        }

        // POST: Categories/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("CategoryId,CategoryImageFile,CategoryName,CategoryTitle,CategoryDescription,CategoryImage,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblCategory tblCategory)
        {
            if (id != tblCategory.CategoryId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    if (tblCategory.CategoryImageFile != null)
                    {

                        var fileName = Path.GetFileNameWithoutExtension(tblCategory.CategoryImageFile.FileName);
                        var fileExtension = Path.GetExtension(tblCategory.CategoryImageFile.FileName);
                        var Image = $"{fileName}_{Guid.NewGuid().ToString()}.{fileExtension}";

                        string wwwRootPath = _webHostEnvironment.WebRootPath;
                        string UploadedFolder = $"/Uploadimages/BrandImages/";




                        var basePath = Path.Combine(wwwRootPath + UploadedFolder);



                        bool basePathExists = System.IO.Directory.Exists(basePath);



                        if (!basePathExists) Directory.CreateDirectory(basePath);



                        var filePath = Path.Combine(basePath, Image);
                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            tblCategory.CategoryImageFile.CopyTo(stream);


                        }

                        string imageURL = UploadedFolder + Image;
                        tblCategory.CategoryImage = imageURL;
                    }
                    _context.Update(tblCategory);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblCategoryExists(tblCategory.CategoryId))
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
            return View(tblCategory);
        }

        // GET: Categories/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblCategory = await _context.TblCategories
                .FirstOrDefaultAsync(m => m.CategoryId == id);
            if (tblCategory == null)
            {
                return NotFound();
            }

            return View(tblCategory);
        }

        // POST: Categories/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblCategory = await _context.TblCategories.FindAsync(id);
            if (tblCategory != null)
            {
                tblCategory.MDelete = true;
                _context.TblCategories.Update(tblCategory);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblCategoryExists(int id)
        {
            return _context.TblCategories.Any(e => e.CategoryId == id);
        }
    }
}

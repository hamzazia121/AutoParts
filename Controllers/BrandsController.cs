

using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;
using Microsoft.AspNetCore.Authorization;

namespace AutoPartsHub.Controllers
{

    [CustomAuthorization]
    [Authorize(Roles = "Admin")]
    public class BrandsController : Controller
    {
        private readonly AutoPartsHubContext _context;
        private readonly IWebHostEnvironment _hostingEnvironment;

        public BrandsController(AutoPartsHubContext context, IWebHostEnvironment hostingEnvironment)
        {
            _context = context;
            _hostingEnvironment = hostingEnvironment;
        }

        // GET: Brands
        public async Task<IActionResult> Index()
        {
            var brands = await _context.TblBrands
            .Where(b => b.MDelete != null && b.MDelete == false)
          .ToListAsync();
            return View(brands);
        }

        // GET: Brands/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblBrand = await _context.TblBrands
                .FirstOrDefaultAsync(m => m.BrandId == id);
            if (tblBrand == null)
            {
                return NotFound();
            }

            return View(tblBrand);
        }

        // GET: Brands/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Brands/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        //public async Task<IActionResult> Create([Bind("BrandId,BrandName,BrandTitle,BrandShortName,BrandDescription,BrandImage,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblBrand tblBrand)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        var path = _hostingEnvironment.WebRootPath; 
        //        var filePath = "Images/"


        //        _context.Add(tblBrand);
        //        await _context.SaveChangesAsync();
        //        return RedirectToAction(nameof(Index));
        //    }
        //    return View(tblBrand);
        //}


        public async Task<IActionResult> Create([Bind("BrandId,BrandImageFile,BrandName,BrandTitle,BrandShortName,BrandDescription,BrandImage,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblBrand tblBrand)
        {
            if (ModelState.IsValid)
            {
                // Check if an image file is uploaded

                if (tblBrand.BrandImageFile != null)
                {

                    var fileName = Path.GetFileNameWithoutExtension(tblBrand.BrandImageFile.FileName);
                    var fileExtension = Path.GetExtension(tblBrand.BrandImageFile.FileName);
                    var Image = $"{fileName}_{Guid.NewGuid().ToString()}.{fileExtension}";

                    string wwwRootPath = _hostingEnvironment.WebRootPath;
                    string UploadedFolder = $"/Uploadimages/BrandImages/";




                    var basePath = Path.Combine(wwwRootPath + UploadedFolder);



                    bool basePathExists = System.IO.Directory.Exists(basePath);



                    if (!basePathExists) Directory.CreateDirectory(basePath);



                    var filePath = Path.Combine(basePath, Image);
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        tblBrand.BrandImageFile.CopyTo(stream);


                    }

                    string imageURL = UploadedFolder + Image;
                    tblBrand.BrandImage = imageURL;
                }

              

                _context.Add(tblBrand);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblBrand);
        }
        // GET: Brands/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblBrand = await _context.TblBrands.FindAsync(id);
            if (tblBrand == null)
            {
                return NotFound();
            }
            return View(tblBrand);
        }

        // POST: Brands/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("BrandId,BrandName,BrandImageFile,BrandTitle,BrandShortName,BrandDescription,BrandImage,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblBrand tblBrand)
        {
            if (id != tblBrand.BrandId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    if (tblBrand.BrandImageFile != null)
                    {

                        var fileName = Path.GetFileNameWithoutExtension(tblBrand.BrandImageFile.FileName);
                        var fileExtension = Path.GetExtension(tblBrand.BrandImageFile.FileName);
                        var Image = $"{fileName}_{Guid.NewGuid().ToString()}.{fileExtension}";

                        string wwwRootPath = _hostingEnvironment.WebRootPath;
                        string UploadedFolder = $"/Uploadimages/BrandImages/";




                        var basePath = Path.Combine(wwwRootPath + UploadedFolder);



                        bool basePathExists = System.IO.Directory.Exists(basePath);



                        if (!basePathExists) Directory.CreateDirectory(basePath);



                        var filePath = Path.Combine(basePath, Image);
                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            tblBrand.BrandImageFile.CopyTo(stream);


                        }

                        string imageURL = UploadedFolder + Image;
                        tblBrand.BrandImage = imageURL;
                    }
                    _context.Update(tblBrand);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblBrandExists(tblBrand.BrandId))
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
            return View(tblBrand);
        }

        // GET: Brands/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblBrand = await _context.TblBrands
                .FirstOrDefaultAsync(m => m.BrandId == id);
            if (tblBrand == null)
            {
                return NotFound();
            }

            return View(tblBrand);
        }

        // POST: Brands/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblBrand = await _context.TblBrands.FindAsync(id);
            if (tblBrand != null)
            {
                tblBrand.MDelete = true; // Set the soft delete flag to true
                _context.TblBrands.Update(tblBrand); // Mark the entity as modified
                await _context.SaveChangesAsync();
            }
            return RedirectToAction(nameof(Index));
        }


        private bool TblBrandExists(int id)
        {
            return _context.TblBrands.Any(e => e.BrandId == id);
        }
    }
}

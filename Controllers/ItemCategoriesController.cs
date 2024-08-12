using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using AutoPartsHub.Models;

namespace AutoPartsHub.Controllers
{
    [CustomAuthorization]

    public class ItemCategoriesController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ItemCategoriesController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: ItemCategories
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = _context.TblItemCategories.Include(t => t.Category).Include(t=>t.Item);
            return View(await autoPartsHubContext.ToListAsync());
        }

        // GET: ItemCategories/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemCategory = await _context.TblItemCategories
                .Include(t => t.Category)
                .Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ItemCategoryId == id);
            if (tblItemCategory == null)
            {
                return NotFound();
            }

            return View(tblItemCategory);
        }

        // GET: ItemCategories/Create
        public IActionResult Create()
        {
            ViewData["CategoryId"] = new SelectList(_context.TblCategories, "CategoryId", "CategoryName");
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            return View();
        }

        // POST: ItemCategories/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ItemCategoryId,CategoryId,ItemId,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemCategory tblItemCategory)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblItemCategory);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["CategoryId"] = new SelectList(_context.TblCategories, "CategoryId", "CategoryName", tblItemCategory.CategoryId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemCategory.ItemId);
            return View(tblItemCategory);
        }

        // GET: ItemCategories/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemCategory = await _context.TblItemCategories.FindAsync(id);
            if (tblItemCategory == null)
            {
                return NotFound();
            }
            ViewData["CategoryId"] = new SelectList(_context.TblCategories, "CategoryId", "CategoryName", tblItemCategory.CategoryId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemCategory.ItemId);

            return View(tblItemCategory);
        }

        // POST: ItemCategories/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemCategoryId,CategoryId,ItemId,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemCategory tblItemCategory)
        {
            if (id != tblItemCategory.ItemCategoryId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblItemCategory);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemCategoryExists(tblItemCategory.ItemCategoryId))
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
            ViewData["CategoryId"] = new SelectList(_context.TblCategories, "CategoryId", "CategoryName", tblItemCategory.CategoryId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemCategory.ItemId);

            return View(tblItemCategory);
        }

        // GET: ItemCategories/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemCategory = await _context.TblItemCategories
                .Include(t => t.Category).Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ItemCategoryId == id);
            if (tblItemCategory == null)
            {
                return NotFound();
            }

            return View(tblItemCategory);
        }

        // POST: ItemCategories/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblItemCategory = await _context.TblItemCategories.FindAsync(id);
            if (tblItemCategory != null)
            {
                tblItemCategory.MDelete=true;
                _context.TblItemCategories.Update(tblItemCategory);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblItemCategoryExists(int id)
        {
            return _context.TblItemCategories.Any(e => e.ItemCategoryId == id);
        }
    }
}

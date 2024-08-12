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
    public class ItemSizesController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ItemSizesController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: ItemSizes
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = _context.TblItemSizes.Include(t => t.Item).Include(t => t.Size);
            return View(await autoPartsHubContext.ToListAsync());
        }

        // GET: ItemSizes/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemSize = await _context.TblItemSizes
                .Include(t => t.Item).Where(a => a.MDelete == null || a.MDelete == false)
                .Include(t => t.Size).Where(a => a.MDelete == null || a.MDelete == false)
                .FirstOrDefaultAsync(m => m.ItemSizeId == id);
            if (tblItemSize == null)
            {
                return NotFound();
            }

            return View(tblItemSize);
        }

        // GET: ItemSizes/Create
        public IActionResult Create()
        {
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            ViewData["SizeId"] = new SelectList(_context.TblSizes, "SizeId", "SizeName");
            return View();
        }

        // POST: ItemSizes/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ItemSizeId,SizeId,ItemId,SizePrice,IsDefault,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemSize tblItemSize)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblItemSize);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemSize.ItemId);
            ViewData["SizeId"] = new SelectList(_context.TblSizes, "SizeId", "SizeName", tblItemSize.SizeId);
            return View(tblItemSize);
        }

        // GET: ItemSizes/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemSize = await _context.TblItemSizes.FindAsync(id);
            if (tblItemSize == null)
            {
                return NotFound();
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemSize.ItemId);
            ViewData["SizeId"] = new SelectList(_context.TblSizes, "SizeId", "SizeName", tblItemSize.SizeId);
            return View(tblItemSize);
        }

        // POST: ItemSizes/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemSizeId,SizeId,ItemId,SizePrice,IsDefault,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemSize tblItemSize)
        {
            if (id != tblItemSize.ItemSizeId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblItemSize);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemSizeExists(tblItemSize.ItemSizeId))
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
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemSize.ItemId);
            ViewData["SizeId"] = new SelectList(_context.TblSizes, "SizeId", "SizeName", tblItemSize.SizeId);
            return View(tblItemSize);
        }

        // GET: ItemSizes/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemSize = await _context.TblItemSizes
                .Include(t => t.Item)
                .Include(t => t.Size)
                .FirstOrDefaultAsync(m => m.ItemSizeId == id);
            if (tblItemSize == null)
            {
                return NotFound();
            }

            return View(tblItemSize);
        }

        // POST: ItemSizes/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblItemSize = await _context.TblItemSizes.FindAsync(id);
            if (tblItemSize != null)
            {
                _context.TblItemSizes.Remove(tblItemSize);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TblItemSizeExists(int id)
        {
            return _context.TblItemSizes.Any(e => e.ItemSizeId == id);
        }
    }
}

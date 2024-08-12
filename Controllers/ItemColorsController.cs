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

    public class ItemColorsController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ItemColorsController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: ItemColors
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = _context.TblItemColors.Include(t => t.Color).Include(t => t.Item);
            return View(await autoPartsHubContext.ToListAsync());
        }

        // GET: ItemColors/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemColor = await _context.TblItemColors
                .Include(t => t.Color)
                .Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ColorId == id);
            if (tblItemColor == null)
            {
                return NotFound();
            }

            return View(tblItemColor);
        }

        // GET: ItemColors/Create
        public IActionResult Create()
        {
            ViewData["ColorId"] = new SelectList(_context.TblColors, "ColorId", "ColorName");
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            return View();
        }

        // POST: ItemColors/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ColorId,ItemId,ColorPrice,IsDefault,ItemColor,MDelete,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy")] TblItemColor tblItemColor)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblItemColor);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["ColorId"] = new SelectList(_context.TblColors, "ColorId", "ColorName", tblItemColor.ColorId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemColor.ItemId);
            return View(tblItemColor);
        }

        // GET: ItemColors/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemColor = await _context.TblItemColors.FindAsync(id);
            if (tblItemColor == null)
            {
                return NotFound();
            }
            ViewData["ColorId"] = new SelectList(_context.TblColors, "ColorId", "ColorName", tblItemColor.ColorId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemColor.ItemId);
            return View(tblItemColor);
        }

        // POST: ItemColors/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemColorId,ItemId,ColorPrice,IsDefault,ColorId,MDelete,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy")] TblItemColor tblItemColor)
        {
            if (id != tblItemColor.ItemColorId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblItemColor);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemColorExists(tblItemColor.ItemColorId))
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
            ViewData["ColorId"] = new SelectList(_context.TblColors, "ColorId", "ColorName", tblItemColor.ColorId);
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemColor.ItemId);
            return View(tblItemColor);
        }

        // GET: ItemColors/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemColor = await _context.TblItemColors
                .Include(t => t.Color)
                .Include(t => t.Item)
                .FirstOrDefaultAsync(m => m.ColorId == id);
            if (tblItemColor == null)
            {
                return NotFound();
            }

            return View(tblItemColor);
        }

        // POST: ItemColors/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblItemColor = await _context.TblItemColors.FindAsync(id);
            if (tblItemColor != null)
            {
                _context.TblItemColors.Remove(tblItemColor);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TblItemColorExists(int id)
        {
            return _context.TblItemColors.Any(e => e.ColorId == id);
        }
    }
}

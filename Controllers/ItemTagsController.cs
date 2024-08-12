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
    public class ItemTagsController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ItemTagsController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: ItemTags
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = _context.TblItemTags.Include(t => t.Item).Include(t => t.Tag);
            return View(await autoPartsHubContext.ToListAsync());
        }

        // GET: ItemTags/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemTag = await _context.TblItemTags
                .Include(t => t.Item)
                .Include(t => t.Tag)
                .FirstOrDefaultAsync(m => m.ItemTagId == id);
            if (tblItemTag == null)
            {
                return NotFound();
            }

            return View(tblItemTag);
        }

        // GET: ItemTags/Create
        public IActionResult Create()
        {
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName");
            ViewData["TagId"] = new SelectList(_context.TblTags, "TagId", "TagName");
            return View();
        }

        // POST: ItemTags/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ItemTagId,TagId,TagName,ItemName,ItemId,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemTag tblItemTag)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblItemTag);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemTag.ItemId);
            ViewData["TagId"] = new SelectList(_context.TblTags, "TagId", "TagName", tblItemTag.TagId);
            return View(tblItemTag);
        }

        // GET: ItemTags/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemTag = await _context.TblItemTags.FindAsync(id);
            if (tblItemTag == null)
            {
                return NotFound();
            }
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemTag.ItemId);
            ViewData["TagId"] = new SelectList(_context.TblTags, "TagId", "TagName", tblItemTag.TagId);
            return View(tblItemTag);
        }

        // POST: ItemTags/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ItemTagId,TagId,TagName,ItemId,ItemName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblItemTag tblItemTag)
        {
            if (id != tblItemTag.ItemTagId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblItemTag);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblItemTagExists(tblItemTag.ItemTagId))
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
            ViewData["ItemId"] = new SelectList(_context.TblItems, "ItemId", "ItemName", tblItemTag.ItemId);
            ViewData["TagId"] = new SelectList(_context.TblTags, "TagId", "TagName", tblItemTag.TagId);
            return View(tblItemTag);
        }

        // GET: ItemTags/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblItemTag = await _context.TblItemTags
                .Include(t => t.Item)
                .Include(t => t.Tag)
                .FirstOrDefaultAsync(m => m.ItemTagId == id);
            if (tblItemTag == null)
            {
                return NotFound();
            }

            return View(tblItemTag);
        }

        // POST: ItemTags/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblItemTag = await _context.TblItemTags.FindAsync(id);
            if (tblItemTag != null)
            {
                tblItemTag.MDelete = true;
                _context.TblItemTags.Update(tblItemTag);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblItemTagExists(int id)
        {
            return _context.TblItemTags.Any(e => e.ItemTagId == id);
        }
    }
}

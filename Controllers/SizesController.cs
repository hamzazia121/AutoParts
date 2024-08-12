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
    public class SizesController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public SizesController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: Sizes
        public async Task<IActionResult> Index()
        {
            return View(await _context.TblSizes.ToListAsync());
        }

        // GET: Sizes/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblSize = await _context.TblSizes
                .FirstOrDefaultAsync(m => m.SizeId == id);
            if (tblSize == null)
            {
                return NotFound();
            }

            return View(tblSize);
        }

        // GET: Sizes/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Sizes/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("SizeId,SizeName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblSize tblSize)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblSize);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblSize);
        }

        // GET: Sizes/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblSize = await _context.TblSizes.FindAsync(id);
            if (tblSize == null)
            {
                return NotFound();
            }
            return View(tblSize);
        }

        // POST: Sizes/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("SizeId,SizeName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblSize tblSize)
        {
            if (id != tblSize.SizeId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblSize);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblSizeExists(tblSize.SizeId))
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
            return View(tblSize);
        }

        // GET: Sizes/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblSize = await _context.TblSizes
                .FirstOrDefaultAsync(m => m.SizeId == id);
            if (tblSize == null)
            {
                return NotFound();
            }

            return View(tblSize);
        }

        // POST: Sizes/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblSize = await _context.TblSizes.FindAsync(id);
            if (tblSize != null)
            {
                _context.TblSizes.Remove(tblSize);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TblSizeExists(int id)
        {
            return _context.TblSizes.Any(e => e.SizeId == id);
        }
    }
}

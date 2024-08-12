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
    public class ColorsController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public ColorsController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: Colors
        public async Task<IActionResult> Index()
        {
            return View(await _context.TblColors.ToListAsync());
        }

        // GET: Colors/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblColor = await _context.TblColors
                .FirstOrDefaultAsync(m => m.ColorId == id);
            if (tblColor == null)
            {
                return NotFound();
            }

            return View(tblColor);
        }

        // GET: Colors/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Colors/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ColorId,ColorName,CreatedAt,CreatedBy,UpdatedAt,UpdateBy,MDelete")] TblColor tblColor)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblColor);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblColor);
        }

        // GET: Colors/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblColor = await _context.TblColors.FindAsync(id);
            if (tblColor == null)
            {
                return NotFound();
            }
            return View(tblColor);
        }

        // POST: Colors/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ColorId,ColorName,CreatedAt,CreatedBy,UpdatedAt,UpdateBy,MDelete")] TblColor tblColor)
        {
            if (id != tblColor.ColorId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblColor);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblColorExists(tblColor.ColorId))
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
            return View(tblColor);
        }

        // GET: Colors/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblColor = await _context.TblColors
                .FirstOrDefaultAsync(m => m.ColorId == id);
            if (tblColor == null)
            {
                return NotFound();
            }

            return View(tblColor);
        }

        // POST: Colors/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblColor = await _context.TblColors.FindAsync(id);
            if (tblColor != null)
            {
                tblColor.MDelete=true;
                _context.TblColors.Remove(tblColor);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblColorExists(int id)
        {
            return _context.TblColors.Any(e => e.ColorId == id);
        }
    }
}

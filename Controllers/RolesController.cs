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
    public class RolesController : Controller
    {
        private readonly AutoPartsHubContext _context;
         
        public RolesController(AutoPartsHubContext context)
        {
            _context = context;

         
        }

	// GET: Roles
	public async Task<IActionResult> Index()
        {
            var role = await _context.TblRolls
           .Where(b => b.MDelete == false || b.MDelete == null)
         .ToListAsync();
            return View(role);
          
        }

        // GET: Roles/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblRoll = await _context.TblRolls
                .FirstOrDefaultAsync(m => m.RollId == id);
            if (tblRoll == null)
            {
                return NotFound();
            }

            return View(tblRoll);
        }

        // GET: Roles/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Roles/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("RollId,RollName,CreatedAt,CreatedBy,UptadedAt,UpdatedBy,MDelete")] TblRoll tblRoll)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblRoll);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(tblRoll);
        }

        // GET: Roles/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblRoll = await _context.TblRolls.FindAsync(id);
            if (tblRoll == null)
            {
                return NotFound();
            }
            return View(tblRoll);
        }

        // POST: Roles/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("RollId,RollName,CreatedAt,CreatedBy,UptadedAt,UpdatedBy,MDelete")] TblRoll tblRoll)
        {
            if (id != tblRoll.RollId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblRoll);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblRollExists(tblRoll.RollId))
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
            return View(tblRoll);
        }

        // GET: Roles/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblRoll = await _context.TblRolls
                .FirstOrDefaultAsync(m => m.RollId == id);
            if (tblRoll == null)
            {
                return NotFound();
            }

            return View(tblRoll);
        }

        // POST: Roles/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblRoll = await _context.TblRolls.FindAsync(id);
            if (tblRoll != null)
            {
                tblRoll.MDelete = true;

                _context.Update(tblRoll);
            await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblRollExists(int id)
        {
            return _context.TblRolls.Any(e => e.RollId == id);
        }
    }
}

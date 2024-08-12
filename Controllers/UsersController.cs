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
    public class UsersController : Controller
    {
        private readonly AutoPartsHubContext _context;

        public UsersController(AutoPartsHubContext context)
        {
            _context = context;
        }

        // GET: Users
        public async Task<IActionResult> Index()
        {
            var autoPartsHubContext = await _context.TblUsers.Include(t => t.Roll).Where(b => b.MDelete == false || b.MDelete == null)
          .ToListAsync();
            return View(autoPartsHubContext);
        }

        // GET: Users/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblUser = await _context.TblUsers
                .Include(t => t.Roll)
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (tblUser == null)
            {
                return NotFound();
            }

            return View(tblUser);
        }

        // GET: Users/Create
        public IActionResult Create()
        {
            ViewData["RollId"] = new SelectList(_context.TblRolls, "RollId", "RollName");
            return View();
        }

        // POST: Users/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("UserId,UserName,Email,PhoneNumber,Password,RollId,RollName,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblUser tblUser)
        {
            if (ModelState.IsValid)
            {
                _context.Add(tblUser);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["RollId"] = new SelectList(_context.TblRolls, "RollId", "RollName", tblUser.RollId);
            return View(tblUser);
        }

        // GET: Users/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblUser = await _context.TblUsers.FindAsync(id);
            if (tblUser == null)
            {
                return NotFound();
            }
            ViewData["RollId"] = new SelectList(_context.TblRolls, "RollId", "RollName", tblUser.RollId);
            return View(tblUser);
        }

        // POST: Users/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("UserId,UserName,Email,PhoneNumber,Password,RollId,CreatedAt,CreatedBy,UpdatedAt,UpdatedBy,MDelete")] TblUser tblUser)
        {
            if (id != tblUser.UserId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(tblUser);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!TblUserExists(tblUser.UserId))
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
            ViewData["RollId"] = new SelectList(_context.TblRolls, "RollId", "RollId", tblUser.RollId);
            return View(tblUser);
        }

        // GET: Users/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var tblUser = await _context.TblUsers
                .Include(t => t.Roll)
                .FirstOrDefaultAsync(m => m.UserId == id);
            if (tblUser == null)
            {
                return NotFound();
            }

            return View(tblUser);
        }

        // POST: Users/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var tblUser = await _context.TblUsers.FindAsync(id);
            if (tblUser != null)
            {
                tblUser.MDelete = true; // Set the soft delete flag to true
                _context.TblUsers.Update(tblUser);
                await _context.SaveChangesAsync();
            }

            return RedirectToAction(nameof(Index));
        }

        private bool TblUserExists(int id)
        {
            return _context.TblUsers.Any(e => e.UserId == id);
        }
    }
}

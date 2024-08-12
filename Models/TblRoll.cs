using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblRoll
{
    public int RollId { get; set; }

    public string? RollName { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UptadedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblUser> TblUsers { get; set; } = new List<TblUser>();
}

using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblColor
{
    public int ColorId { get; set; }

    public string ColorName { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdateBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblItemColor> TblItemColors { get; set; } = new List<TblItemColor>();
}

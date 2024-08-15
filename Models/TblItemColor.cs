using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblItemColor
{
    public int ItemColorId { get; set; }

    public int? ItemId { get; set; }

    public int? ColorId { get; set; }

    public decimal? ColorPrice { get; set; }

    public Boolean IsDefault { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? Updatedby { get; set; }

    public bool? MDelete { get; set; }

    public virtual TblColor? Color { get; set; }

    public virtual TblItem? Item { get; set; }
}

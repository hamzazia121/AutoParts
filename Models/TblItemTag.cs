using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblItemTag
{
    public int ItemTagId { get; set; }

    public int? TagId { get; set; }

    public int? ItemId { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual TblItem? Item { get; set; }

    public virtual TblTag? Tag { get; set; }
}

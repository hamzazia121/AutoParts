using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblTag
{
    public int TagId { get; set; }

    public string TagName { get; set; } = null!;

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblItemTag> TblItemTags { get; set; } = new List<TblItemTag>();
}

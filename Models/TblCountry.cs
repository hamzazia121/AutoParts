using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models;

public partial class TblCountry
{
    public int CountryId { get; set; }

    public string? CountryName { get; set; }

    public DateTime? CreatedAt { get; set; }

    public int? CreatedBy { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public int? UpdatedBy { get; set; }

    public bool MDelete { get; set; }

    public virtual ICollection<TblOrdersMain> TblOrdersMains { get; set; } = new List<TblOrdersMain>();
}

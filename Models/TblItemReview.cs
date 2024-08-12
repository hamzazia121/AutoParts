using System;
using System.Collections.Generic;

namespace AutoPartsHub.Models
{
    public partial class TblItemReview
    {
        public int ReviewId { get; set; }

        public string ReviewName { get; set; } = null!;

        public string? ReviewText { get; set; }
        public int ItemId { get; set; } 

        public DateTime? ReviewDate { get; set; }

        public byte? Rating { get; set; }

        public DateTime? CreatedAt { get; set; }

        public int? CreatedBy { get; set; }

        public DateTime? UpdatedAt { get; set; }

        public int? UpdatedBy { get; set; }

        public bool Mdelete { get; set; }
        public virtual TblItem Item { get; set; } = null!;
    }
}

namespace AutoPartsHub.Models
{
    public class CheckoutViewModel
    {
        public TblOrdersMain ?TblOrdersMain { get; set; }
        public List<TblItem>? TblItems { get; set; }
        public List<TblOrderDetail>? OrderDetail { get; set; }
        public List<TblOrderDetail>? OrderDetails { get; set; }
		public List<TblOrderDetail>? TodayOrderDetail { get; set; } 
		public List<TblOrderDetail>? TodayOrderDetails { get; set; } 

	}
}

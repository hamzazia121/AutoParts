namespace AutoPartsHub.Models;

    public class CartModel
    {
        public int ProductId { get; set; }
        public int Quantity { get; set; }
    }

    public class ListCartModel
    {
       public List<CartModel> Carts { get; set; }

    public ListCartModel()
    {
        Carts = new List<CartModel>();
    }
}

    


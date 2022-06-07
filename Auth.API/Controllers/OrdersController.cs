using System;
using System.Collections.Generic;
using System.Web.Http;
using B2CAuth.Api.Filters;

namespace B2CAuth.Api.Controllers
{
    [B2CAuthorize("CanDoAnything")]
    [RoutePrefix("api/Orders")]
    public class OrdersController : ApiController
    {
        [Route("")]
        public IHttpActionResult Get()
        {
            var orderEntitis = new List<OrderModel>() 
            {
                new OrderModel()
                {
                    OrderID = "1",
                    ShipperName = "Evergreen",
                    ShipperCity = "Tampa",
                    TS = DateTime.Now
                },
                new OrderModel()
                {
                    OrderID = "2",
                    ShipperName = "MSC",
                    ShipperCity = "Panama City",
                    TS = DateTime.Now
                },
                new OrderModel()
                {
                    OrderID = "3",
                    ShipperName = "Lloyd",
                    ShipperCity = "Miami",
                    TS = DateTime.Now
                }
            };
            return Ok(orderEntitis);
        }

        [Route("{orderId}")]
        public IHttpActionResult Get(string orderId)
        {
            var orderEntity = new OrderModel()
            {
                OrderID = "1",
                ShipperName = "Evergreen",
                ShipperCity = "Tampa",
                TS = DateTime.Now
            };

            return Ok(orderEntity);
        }

        [Route("")]
        public IHttpActionResult Post(OrderModel order)
        {
            return Ok(order);
        }
    }

    #region Classes

    public class OrderModel
    {
        public string OrderID { get; set; }
        public string ShipperName { get; set; }
        public string ShipperCity { get; set; }
        public DateTimeOffset TS { get; set; }
    }

    #endregion
}
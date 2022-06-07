using System;
using System.Web.Http;
using B2CAuth.Api.Filters;

namespace B2CAuth.Api.Controllers
{
    [B2CAuthorize("NeedAdminRights")]
    [RoutePrefix("api/protected")]
    public class ProtectedController : ApiController
    {
        [Route("")]
        public IHttpActionResult Get()
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
    }
}

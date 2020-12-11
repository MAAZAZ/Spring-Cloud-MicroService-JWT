package org.glsid.billingservice.feignClient;


import org.glsid.billingservice.model.Product;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.hateoas.PagedModel;
import org.springframework.web.bind.annotation.*;

@FeignClient(name="INVENTORY-SERVICE")
public interface InventoryServiceClient {
    @RequestMapping(method = RequestMethod.GET,value="/products/{id}", produces = "application/json")
    Product getProductById(@PathVariable("id") Long id);
    @RequestMapping(method = RequestMethod.GET,value="/products", produces = "application/json")
    PagedModel<Product> pageProducts();
}

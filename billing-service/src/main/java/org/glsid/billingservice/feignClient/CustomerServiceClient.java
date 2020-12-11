package org.glsid.billingservice.feignClient;

import org.glsid.billingservice.model.Customer;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@FeignClient(name="CUSTOMER-SERVICE")
public interface CustomerServiceClient {
    @RequestMapping(method = RequestMethod.GET, value="/customers/{id}", produces = "application/json")
    Customer getCustomerById(@PathVariable("id") Long id);
}

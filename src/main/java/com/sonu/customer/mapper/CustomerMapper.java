package com.sonu.customer.mapper;

import com.sonu.customer.beans.entity.Customer;
import com.sonu.customer.beans.request.CustomerRequest;
import com.sonu.customer.beans.response.CustomerResponse;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface CustomerMapper {

    @Mapping(target = "addresses", source = "addresses")
    Customer prepareRequest(CustomerRequest customerRequest);

    @Mapping(target = "addresses", source = "addresses")
    CustomerResponse prepareResponse(Customer customer);
}

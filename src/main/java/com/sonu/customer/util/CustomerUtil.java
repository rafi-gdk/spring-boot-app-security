package com.sonu.customer.util;


import com.sonu.customer.beans.entity.Customer;
import com.sonu.customer.beans.request.CustomerRequest;
import com.sonu.customer.beans.response.CustomerResponse;
import com.sonu.customer.mapper.CustomerMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CustomerUtil {

    @Autowired
    CustomerMapper mapper;

    public Customer buildCustomerRequest(CustomerRequest customerRequest) {
        Customer customer = mapper.prepareRequest(customerRequest);
        return customer;
    }

    public CustomerResponse buildCustomerResponse(Customer customer) {
        CustomerResponse customerResponse = mapper.prepareResponse(customer);
        return customerResponse;
    }
}


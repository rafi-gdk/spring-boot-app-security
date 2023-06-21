package com.sonu.customer.service;

import com.sonu.customer.beans.request.CustomerRequest;
import com.sonu.customer.beans.response.CustomerResponse;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface CustomerService {

    CustomerResponse getCustomer(String customerId);

    List<CustomerResponse> getAllCustomers();

    CustomerResponse updateCustomer(CustomerRequest customerRequest);

    String deleteCustomer(String customerId);

    CustomerResponse addCustomer(CustomerRequest customerRequest);
}

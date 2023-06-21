package com.sonu.customer.service;

import com.sonu.customer.beans.entity.Customer;
import com.sonu.customer.beans.request.CustomerRequest;
import com.sonu.customer.beans.response.CustomerResponse;
import com.sonu.customer.exception.CustomerDataException;
import com.sonu.customer.repository.CustomerRepository;
import com.sonu.customer.util.CustomerUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@Slf4j
public class CustomerServiceImpl implements CustomerService {

    @Autowired
    CustomerRepository repository;

    @Autowired
    CustomerUtil customerUtil;

    @Override
    public CustomerResponse getCustomer(String customerId) {
        CustomerResponse response;
        try {
            Optional<Customer> customer = repository.findById(customerId);
            if (customer.isPresent()) {
                response = customerUtil.buildCustomerResponse(customer.get());
                log.info("getCustomer Response for " + customerId + " " + response);
            } else {
                throw new CustomerDataException("Customer Not Found");
            }
        } catch (Exception e) {
            log.error("Exception Occurred in getCustomer: " + e);
            throw new CustomerDataException(e);
        }
        return response;
    }

    @Override
    public List<CustomerResponse> getAllCustomers() {
        List<CustomerResponse> customerList;
        try {
            List<Customer> customers = repository.findAll();
            customerList = customers.stream().map(i -> customerUtil.buildCustomerResponse(i)).collect(Collectors.toList());
            log.info("getAllCustomers Response " + customerList);
        } catch (Exception e) {
            log.error("Exception Occurred in getAllCustomers: " + e);
            throw new CustomerDataException(e);
        }
        return customerList;
    }

    @Override
    public CustomerResponse addCustomer(CustomerRequest customerRequest) {
        CustomerResponse customerResponse;
        try {
            Optional<Customer> optionalCustomer = repository.findById(customerRequest.getCustomerId());
            if (optionalCustomer.isPresent()) {
                throw new CustomerDataException("Customer Already Exist");
            } else {
                Customer customer = repository.save(customerUtil.buildCustomerRequest(customerRequest));
                if (customer != null) {
                    customerResponse = customerUtil.buildCustomerResponse(customer);
                    log.info("addCustomer Response " + customerResponse);
                } else {
                    throw new CustomerDataException("Customer Insert Failed");
                }
            }
        } catch (Exception e) {
            log.error("Exception Occurred in addCustomer: " + e);
            throw new CustomerDataException(e);
        }
        return customerResponse;
    }

    @Override
    public CustomerResponse updateCustomer(CustomerRequest customerRequest) {
        CustomerResponse customerResponse;
        try {
            Optional<Customer> optionalCustomer = repository.findById(customerRequest.getCustomerId());
            if (optionalCustomer.isPresent()) {
                Customer customer = repository.save(customerUtil.buildCustomerRequest(customerRequest));
                if (customer != null) {
                    customerResponse = customerUtil.buildCustomerResponse(customer);
                    log.info("updateCustomer Response " + customerResponse);
                } else {
                    throw new CustomerDataException("Customer Insert Failed");
                }
            } else {
                throw new CustomerDataException("Customer Not Found");
            }
        } catch (Exception e) {
            log.error("Exception Occurred in updateCustomer: " + e);
            throw new CustomerDataException(e);
        }
        return customerResponse;
    }

    @Override
    public String deleteCustomer(String customerId) {
        try {
            repository.deleteById(customerId);
            log.info("deleteCustomer Response success for " + customerId);
        } catch (Exception e) {
            log.error("Exception Occurred in deleteCustomer: " + e);
            throw new CustomerDataException(e);
        }
        return "success";
    }
}

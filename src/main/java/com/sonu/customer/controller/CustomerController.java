package com.sonu.customer.controller;


import com.sonu.customer.beans.request.CustomerRequest;
import com.sonu.customer.beans.response.CustomerResponse;
import com.sonu.customer.service.CustomerService;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@Validated
@RequestMapping("/customer")
public class CustomerController {

    @Autowired
    CustomerService customerService;

    @GetMapping("/getCustomer/{customerId}")
    public ResponseEntity<CustomerResponse> getCustomer(@PathVariable("customerId") @Size(min = 8, max = 8, message = "CustomerId Length should be 8") String customerId) {
        return new ResponseEntity<>(customerService.getCustomer(customerId), HttpStatus.FOUND);
    }

    @GetMapping("/getAllCustomers")
    public ResponseEntity<List<CustomerResponse>> getAllCustomers() {
        return new ResponseEntity<>(customerService.getAllCustomers(), HttpStatus.FOUND);
    }

    @PostMapping("/addCustomer")
    public ResponseEntity<CustomerResponse> addCustomer(@Validated @RequestBody CustomerRequest CustomerRequest) {
        return new ResponseEntity<>(customerService.addCustomer(CustomerRequest), HttpStatus.CREATED);
    }

    @PutMapping("/updateCustomer")
    public ResponseEntity<CustomerResponse> updateCustomer(@Validated @RequestBody CustomerRequest CustomerRequest) {
        return new ResponseEntity<>(customerService.updateCustomer(CustomerRequest), HttpStatus.ACCEPTED);
    }

    @DeleteMapping("/deleteCustomer/{customerId}")
    public ResponseEntity<String> deleteCustomer(@PathVariable("customerId") @Size(min = 8, max = 8, message = "CustomerId Length should be 8") String customerId) {
        return new ResponseEntity<>(customerService.deleteCustomer(customerId), HttpStatus.ACCEPTED);
    }
}

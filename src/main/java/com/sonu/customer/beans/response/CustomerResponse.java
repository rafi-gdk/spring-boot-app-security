package com.sonu.customer.beans.response;


import com.sonu.customer.beans.request.AddressRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CustomerResponse {

    private String customerId;
    private String customerName;
    private LocalDate customerDOB;
    private Long phoneNumber;
    private String email;
    private String password;
    private List<AddressRequest> addresses;
}

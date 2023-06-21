package com.sonu.customer.beans.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CustomerRequest {

    @NotNull
    @Size(min = 8, max = 8, message = "size must be 10 characters")
    private String customerId;
    @NotNull
    @Size(min = 8, max = 20)
    private String customerName;
    @NotNull
    private LocalDate customerDOB;
    @NotNull
    @Size(min = 10, max = 10, message = "Length must be 10 digits")
    @Pattern(regexp = "^[0-9]+$", message = "Positive numbers only allowed")
    private String phoneNumber;
    @NotNull
    @Email
    private String email;
    @NotNull
    private String password;
    @NotNull
    private List<AddressRequest> addresses;
}

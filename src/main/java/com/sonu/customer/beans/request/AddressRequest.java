package com.sonu.customer.beans.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AddressRequest {

    private String addressId;
    @NotNull
    private String addressType;
    @NotNull
    private String flatNumber;
    @NotNull
    private String plotNumber;
    @NotNull
    private String buildingName;
    @NotNull
    private Integer roadNumber;
    @NotNull
    private String street;
    @NotNull
    private String city;
    @NotNull
    private String country;
    @NotNull
    private Long pinCode;
}

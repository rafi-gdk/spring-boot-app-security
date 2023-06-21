package com.sonu.customer.beans.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "ADDRESS")
public class Address {
    /**
     * in below lines we are using GeneratedValue & GenericGenerator to generate UUID as ID
     * if you manually want to add then you can remove GeneratedValue & GenericGenerator
     */
    @Id
    @GeneratedValue(generator = "gen_uuid")
    @GenericGenerator(name = "gen_uuid", strategy = "uuid2")
    @Column(name = "ADDRESS_ID")
    private String addressId;
    @Column(name = "ADDRESS_TYPE")
    private String addressType;
    @Column(name = "CUSTOMER_ID")
    private String customerId;
    @Column(name = "FLAT_NUMBER")
    private String flatNumber;
    @Column(name = "PLOT_NUMBER")
    private String plotNumber;
    @Column(name = "BUILDING_NAME")
    private String buildingName;
    @Column(name = "ROAD_NUMBER")
    private Integer roadNumber;
    @Column(name = "STREET")
    private String street;
    @Column(name = "CITY")
    private String city;
    @Column(name = "COUNTRY")
    private String country;
    @Column(name = "PIN_CODE")
    private Long pinCode;
}

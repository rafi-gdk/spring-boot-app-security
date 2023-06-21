package com.sonu.customer.security.repository;

import com.sonu.customer.security.beans.UserDetailsBean;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDetailsRepository extends JpaRepository<UserDetailsBean, String> {

}

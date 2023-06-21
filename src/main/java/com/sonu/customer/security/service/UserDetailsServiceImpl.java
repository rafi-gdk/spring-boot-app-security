package com.sonu.customer.security.service;

import com.sonu.customer.security.beans.UserDetailsBean;
import com.sonu.customer.security.repository.UserDetailsRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserDetailsRepository repository;

    @Autowired
    BCryptPasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<UserDetailsBean> byId = repository.findById(username);
        if (!byId.isPresent()) {
            throw new UsernameNotFoundException("User Not found");
        }
        UserDetailsBean userDetails = byId.get();
        return new User(userDetails.getUsername(),
                passwordEncoder.encode(userDetails.getPassword()),
                userDetails.isEnabled(),
                userDetails.isAccountNonExpired(),
                userDetails.isCredentialsNonExpired(),
                userDetails.isAccountNonLocked(),
                userDetails.getAuthorities());
    }
}

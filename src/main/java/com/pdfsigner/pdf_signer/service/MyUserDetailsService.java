// package com.pdfsigner.pdf_signer.service;

// import com.pdfsigner.pdf_signer.model.User;

// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// import com.pdfsigner.pdf_signer.repository.UserRepository;

// @Service
// public class MyUserDetailsService implements UserDetailsService {

//     private final UserRepository userRepository;

//     public MyUserDetailsService(UserRepository userRepository) {
//         this.userRepository = userRepository;
//     }

//     @Override
//     public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//         // Replace with your actual user fetching logic
//         User user = userRepository.findByUsername(username)
//                 .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//         return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
//                 new java.util.ArrayList<>());
//     }
// }

package com.pdfsigner.pdf_signer.service;

import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.User;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.pdfsigner.pdf_signer.repository.UserRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

// @Service
// @Transactional
// public class MyUserDetailsService implements UserDetailsService {

//     private final UserRepository userRepository;

//     public MyUserDetailsService(UserRepository userRepository) {
//         this.userRepository = userRepository;
//     }

//     @Override
//     public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
//         User user = userRepository.findByEmail(email)
//                 .orElseThrow(() -> new UsernameNotFoundException("User not found"));

//         // This avoids the N+1 query problem
//         user.getRoles().size(); // Force load roles

//         return new org.springframework.security.core.userdetails.User(
//                 user.getEmail(),
//                 user.getPassword(),
//                 user.getAuthorities());
//     }
// }
@Slf4j
@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

        private final UserRepository userRepository;

        public UserDetails loadUserByUsername(String email) {
                User user = userRepository.findByEmailWithRoles(email) // Custom query
                                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

                // Convert roles to GrantedAuthority
                List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority(role.name()))
                                .collect(Collectors.toList());

                // return new org.springframework.security.core.userdetails.User(
                // user.getEmail(),
                // user.getPassword(),
                // authorities);

                return org.springframework.security.core.userdetails.User.builder()
                                .username(user.getEmail())
                                .password(user.getPassword())
                                .roles(user.getRoles().stream().map(Role::name).toArray(String[]::new))
                                .accountExpired(!user.isAccountNonExpired())
                                .accountLocked(!user.isAccountNonLocked())
                                .credentialsExpired(!user.isCredentialsNonExpired()) // ← This should be false for valid
                                                                                     // credentials
                                .disabled(!user.isEnabled())
                                .authorities(authorities)
                                .build();

        }

        // Explicit constructor with logging
        // @Autowired
        // public MyUserDetailsService(UserRepository userRepository) {
        // this.userRepository = userRepository;
        // log.info("UserRepository injected: {}", userRepository != null);
        // }

        // @Override
        // public UserDetails loadUserByUsername(String email) {
        // log.info("Loading user by email: {}", email);

        // // Use the correct repository method
        // User user = userRepository.findByEmailWithRoles(email)
        // .orElseThrow(() -> new UsernameNotFoundException("User not found with email:
        // " + email));

        // log.info("User found: {}", user.getEmail());

        // List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
        // .map(role -> new SimpleGrantedAuthority(role.name()))
        // .collect(Collectors.toList());

        // return new org.springframework.security.core.userdetails.User(
        // user.getEmail(),
        // user.getPassword(),
        // authorities);
        // }
}

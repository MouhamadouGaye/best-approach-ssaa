package com.pdfsigner.pdf_signer.service;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.pdfsigner.pdf_signer.dto.AuthResponse;
import com.pdfsigner.pdf_signer.dto.LoginResponse;
import com.pdfsigner.pdf_signer.dto.RegisterRequest;
import com.pdfsigner.pdf_signer.dto.UserDto;
import com.pdfsigner.pdf_signer.excetion.EmailAlreadyExistsException;
import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.request.LoginRequest;
import com.pdfsigner.pdf_signer.util.JwtUtil;

import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UserService {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private MyUserDetailsService userDetailsService;
    private JwtUtil jwtUtil;

    public UserService(UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            MyUserDetailsService userDetailsService,
            JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    // ------------------------Start These authentication are the good
    // one----------------------//

    // public UserDto registerUser(RegisterRequest request) {
    // if (userRepository.existsByEmail(request.getEmail())) {
    // throw new EmailAlreadyExistsException("Email already exists: " +
    // request.getEmail());
    // }

    // User user = User.builder()
    // .username(request.getUsername())
    // .email(request.getEmail())
    // .password(passwordEncoder.encode(request.getPassword()))
    // .createdAt(LocalDateTime.now())
    // .roles(Set.of(Role.USER))
    // .build();

    // User savedUser = userRepository.save(user);

    // return new UserDto(
    // savedUser.getId(),
    // savedUser.getEmail(),
    // savedUser.getUsername(),
    // savedUser.getRoles().stream()
    // .map(Role::name) // This turns Role into String
    // .collect(Collectors.toSet()) // So you're building Set<String>
    // );

    // }

    // public AuthResponse login(LoginRequest loginRequest) {
    // log.info("Login attempt for email: {}", loginRequest.getEmail());

    // User user = userRepository.findByEmailWithRoles(loginRequest.getEmail())
    // .orElseThrow(() -> {
    // log.warn("User not found for email: {}", loginRequest.getEmail());
    // return new UsernameNotFoundException("User not found");
    // });

    // if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()))
    // {
    // log.warn("Password mismatch for user: {}", user.getEmail());
    // throw new BadCredentialsException("Invalid credentials");
    // }

    // UserDetails userDetails =
    // userDetailsService.loadUserByUsername(user.getEmail());
    // String token = jwtUtil.generateToken(userDetails);

    // UserDto userDTO = new UserDto(
    // user.getId(),
    // user.getEmail(),
    // user.getUsername(),
    // user.getRoles().stream()
    // .map(Role::name) // This turns Role into String
    // .collect(Collectors.toSet()) // So you're building Set<String>
    // );

    // return new AuthResponse(token, userDTO);
    // }
    // ------------------------End These authentication are the good
    // one----------------------//

    // public User registerUser(RegisterRequest registerRequest) {
    // // Check if username or email already exists
    // if (userRepository.existsByEmail(registerRequest.getEmail())) {
    // log.info("the email used: {}" + registerRequest.getEmail());
    // throw new EmailAlreadyExistsException("Email already exists" +
    // registerRequest.getEmail());

    // }
    // // Create new User entity
    // User user = new User();
    // user.setUsername(registerRequest.getUsername());
    // user.setPassword(passwordEncoder.encode(registerRequest.getPassword())); //
    // Encode password
    // user.setEmail(registerRequest.getEmail());
    // user.setCreatedAt(LocalDateTime.now());

    // // Assign default role (e.g., ROLE_USER)
    // user.setRoles(Collections.singleton(Role.USER)); // Ensure Role enum exists

    // return userRepository.save(user);
    // }

    // public UserDto registerUser(RegisterRequest request) {
    // log.info("Registering user: {}", request.getEmail());
    // log.info("Password received: {}", request.getPassword());
    // log.info("Password is null: {}", request.getPassword() == null);

    // if (userRepository.existsByEmail(request.getEmail())) {
    // throw new EmailAlreadyExistsException("Email already exists: " +
    // request.getEmail());
    // }

    // // Debug: Check if password is null before encoding
    // if (request.getPassword() == null) {
    // throw new IllegalArgumentException("Password cannot be null");
    // }

    // String encodedPassword = passwordEncoder.encode(request.getPassword());
    // log.info("Encoded password: {}", encodedPassword);

    // User user = User.builder()
    // .username(request.getUsername())
    // .email(request.getEmail())
    // .password(encodedPassword)
    // .createdAt(LocalDateTime.now())
    // .roles(Set.of(Role.USER))
    // .build();

    // try {
    // User savedUser = userRepository.save(user);
    // log.info("User saved successfully: {}", savedUser.getId());

    // return new UserDto(
    // savedUser.getId(),
    // savedUser.getEmail(),
    // savedUser.getUsername(),
    // savedUser.getRoles().stream()
    // .map(Role::name)
    // .collect(Collectors.toSet()));
    // } catch (Exception e) {
    // log.error("Error saving user: {}", e.getMessage());
    // throw e;
    // }
    // }

    // public User registerUser(RegisterRequest registerRequest) {
    // // Check for null password
    // if (registerRequest.getPassword() == null) {
    // throw new IllegalArgumentException("Password cannot be null");
    // }

    // if (userRepository.existsByEmail(registerRequest.getEmail())) {
    // throw new RuntimeException("Email already exists");
    // }

    // // Create new user entity
    // User user = new User();
    // user.setUsername(registerRequest.getUsername());
    // user.setEmail(registerRequest.getEmail());
    // user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
    // user.setCreatedAt(LocalDateTime.now());
    // user.setRoles(Set.of(Role.USER));

    // return userRepository.save(user);
    // }

    // public User getUserByUsername(String username) {
    // return userRepository.findByUsername(username)
    // .orElseThrow(() -> new RuntimeException("User not found"));
    // }

    public User getUserByUsername(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    // public User login(User user) {
    // User foundUser = userRepository.findByEmail(user.getEmail())
    // .orElseThrow(() -> new RuntimeException("User not found"));

    // userRepository.save(foundUser);
    // if (!passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
    // throw new RuntimeException("Invalid password");
    // }
    // return foundUser;

    // }

    // public Map<String, Object> login(LoginRequest loginRequest) {
    // User user = userRepository.findByEmail(loginRequest.getEmail())
    // .orElseThrow(
    // () -> new UsernameNotFoundException("User not found with email: " +
    // loginRequest.getEmail()));

    // if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()))
    // {
    // throw new BadCredentialsException("Invalid email or password");
    // }
    // // For JWT generation we still need a UserDetails object
    // UserDetails userDetails =
    // userDetailsService.loadUserByUsername(user.getEmail());
    // String token = jwtUtil.generateToken(userDetails);

    // Map<String, Object> response = new HashMap<>();
    // response.put("token", token);
    // response.put("user", Map.of(
    // "id", user.getId(),
    // "email", user.getEmail(),
    // "username", user.getUsername()));

    // return response;
    // }

    // public Map<String, Object> loginWithMap(LoginRequest loginRequest) {
    // log.info("Login attempt for email: {}", loginRequest.getEmail());

    // User user = userRepository.findByEmail(loginRequest.getEmail())
    // .orElseThrow(() -> {
    // log.warn("User not found for email: {}", loginRequest.getEmail());
    // return new UsernameNotFoundException("User not found");
    // });

    // log.info("User found: {}", user.getEmail());
    // log.info("Stored password hash: {}", user.getPassword());
    // log.info("Provided password: {}", loginRequest.getPassword());

    // if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()))
    // {
    // log.warn("Password mismatch for user: {}", user.getEmail());
    // throw new BadCredentialsException("Invalid credentials");
    // }

    // log.info("Password matches for user: {}", user.getEmail());

    // UserDetails userDetails =
    // userDetailsService.loadUserByUsername(user.getEmail());
    // log.info("User authorities: {}", userDetails.getAuthorities());

    // String token = jwtUtil.generateToken(userDetails);
    // log.info("Generated JWT token: {}", token);

    // Map<String, Object> response = new HashMap<>();
    // response.put("token", token);
    // response.put("user", Map.of(
    // "id", user.getId(),
    // "email", user.getEmail(),
    // "username", user.getUsername()));

    // return response;
    // }

}

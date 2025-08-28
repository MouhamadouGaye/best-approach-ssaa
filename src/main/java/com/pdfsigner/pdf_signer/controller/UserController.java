package com.pdfsigner.pdf_signer.controller;

import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import com.pdfsigner.pdf_signer.dto.AuthResponse;
import com.pdfsigner.pdf_signer.dto.LoginResponse;
import com.pdfsigner.pdf_signer.dto.RegisterRequest;
import com.pdfsigner.pdf_signer.dto.UserDto;
import com.pdfsigner.pdf_signer.excetion.EmailAlreadyExistsException;
import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.request.LoginRequest;
import com.pdfsigner.pdf_signer.service.UserService;
import com.pdfsigner.pdf_signer.util.JwtUtil;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final UserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    // ------------------------Start These authentication are the good
    // one----------------------//

    // @PostMapping("/register")
    // public ResponseEntity<UserDto> registerUser(@Valid @RequestBody
    // RegisterRequest request) {
    // UserDto registeredUser = userService.registerUser(request);
    // return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    // try {
    // AuthResponse response = userService.login(loginRequest);
    // return ResponseEntity.ok(response);
    // } catch (UsernameNotFoundException | BadCredentialsException e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
    // .body(Map.of("error", e.getMessage()));
    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
    // .body(Map.of("error", "Unexpected error: " + e.getMessage()));
    // }
    // }
    // ------------------------End These authentication are the good
    // one----------------------//

    // @PostMapping("/register")
    // public ResponseEntity<?> registerUser(@RequestBody RegisterRequest user) {
    // try {
    // User registeredUser = userService.registerUser(user);
    // return ResponseEntity.ok(registeredUser);

    // } catch (EmailAlreadyExistsException e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
    // .body("error: " + e.getMessage());
    // } catch (Exception e) {
    // return ResponseEntity.badRequest().body(e.getMessage());
    // }
    // }

    // @PostMapping("/register")
    // public ResponseEntity<UserDto> register(@Valid @RequestBody RegisterRequest
    // request) {
    // System.out.println("Controller received password: " + request.getPassword());
    // // Debug
    // UserDto userDto = userService.registerUser(request);
    // return ResponseEntity.ok(userDto);
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // try {
    // LoginResponse registeredUser = userService.login(request);

    // return ResponseEntity.ok(registeredUser);
    // } catch (Exception e) {
    // return ResponseEntity.badRequest().body(e.getMessage());
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest
    // loginRequest) {
    // try {
    // AuthResponse response = userService.login(loginRequest);
    // return ResponseEntity.ok(response);
    // } catch (UsernameNotFoundException | BadCredentialsException e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest)
    // {
    // try {
    // AuthResponse response = userService.login(loginRequest);
    // return ResponseEntity.ok(response);
    // } catch (UsernameNotFoundException | BadCredentialsException e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
    // .body(Map.of("error", "Invalid email or password"));
    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
    // .body(Map.of("error", "An unexpected error occurred"));
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest
    // loginRequest) {
    // return ResponseEntity.ok(userService.login(loginRequest));
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestBody UserDetails user) {
    // try {
    // User authenticatedUser = userService.login(user);
    // String token = jwtUtil.generateToken(user.getUsername());

    // // ✅ Return a response matching the expected structure
    // Map<String, Object> response = new HashMap<>();
    // response.put("token", token); // Replace with real JWT later
    // response.put("user", Map.of(
    // "id", authenticatedUser.getId(),
    // "email", authenticatedUser.getEmail(),
    // "username", authenticatedUser.getUsername()));

    // return ResponseEntity.ok(response);
    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    // try {
    // UserDetails userDetails =
    // userDetailsService.loadUserByUsername(loginRequest.getUsername());

    // // Debug output - only for development/testing!
    // System.out.println("Raw password from request: " +
    // loginRequest.getPassword());
    // System.out.println("Encoded password from DB: " + userDetails.getPassword());

    // if (!passwordEncoder.matches(loginRequest.getPassword(),
    // userDetails.getPassword())) {
    // throw new BadCredentialsException("Invalid username or password");
    // }

    // // Authenticate the user manually (or use AuthenticationManager)
    // if (!passwordEncoder.matches(loginRequest.getPassword(),
    // userDetails.getPassword())) {
    // throw new BadCredentialsException("Invalid username or password");
    // }

    // User authenticatedUser =
    // userService.getUserByUsername(loginRequest.getUsername());

    // String token = jwtUtil.generateToken(userDetails);

    // Map<String, Object> response = new HashMap<>();
    // response.put("token", token);
    // response.put("user", Map.of(
    // "id", authenticatedUser.getId(),
    // "email", authenticatedUser.getEmail(),
    // "username", authenticatedUser.getUsername()));

    // return ResponseEntity.ok(response);

    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error",
    // e.getMessage()));
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    // try {
    // // Load user by email, not username
    // User userEntity = userService.getUserByEmail(loginRequest.getEmail());

    // if (userEntity == null) {
    // throw new UsernameNotFoundException("User not found with email: " +
    // loginRequest.getEmail());
    // }

    // // Match raw password with hashed password
    // if (!passwordEncoder.matches(loginRequest.getPassword(),
    // userEntity.getPassword())) {
    // throw new BadCredentialsException("Invalid email or password");
    // }

    // // Load UserDetails via your custom service, if needed for JWT
    // UserDetails userDetails =
    // userDetailsService.loadUserByUsername(userEntity.getUsername());

    // String token = jwtUtil.generateToken(userDetails);

    // Map<String, Object> response = new HashMap<>();
    // response.put("token", token);
    // response.put("user", Map.of(
    // "id", userEntity.getId(),
    // "email", userEntity.getEmail(),
    // "username", userEntity.getUsername()));

    // return ResponseEntity.ok(response);

    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error",
    // e.getMessage()));
    // }
    // }

    // @PostMapping("/login")
    // public ResponseEntity<?> loginWithMap(@RequestBody LoginRequest loginRequest)
    // {
    // try {
    // Map<String, Object> response = userService.loginWithMap(loginRequest);
    // return ResponseEntity.ok(response);
    // } catch (Exception e) {
    // return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
    // .body(Map.of("error", e.getMessage()));
    // }
    // }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            User user = userService.getUserByUsername(userDetails.getUsername());
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
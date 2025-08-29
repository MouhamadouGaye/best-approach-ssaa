package com.pdfsigner.pdf_signer.controller;

import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.pdfsigner.pdf_signer.dto.ApiResponse;
import com.pdfsigner.pdf_signer.dto.LoginResponse;
import com.pdfsigner.pdf_signer.dto.RegisterRequest;
import com.pdfsigner.pdf_signer.dto.ResetPasswordRequest;
import com.pdfsigner.pdf_signer.dto.UpdateProfileRequest;
import com.pdfsigner.pdf_signer.dto.UserDto;
import com.pdfsigner.pdf_signer.excetion.EmailAlreadyExistsException;
import com.pdfsigner.pdf_signer.excetion.InvalidTokenException;
import com.pdfsigner.pdf_signer.excetion.TokenExpiredException;
import com.pdfsigner.pdf_signer.excetion.UserAlreadyVerifiedException;
import com.pdfsigner.pdf_signer.excetion.UserNotFoundException;
import com.pdfsigner.pdf_signer.excetion.UsernameAlreadyExistsException;
import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.TokenType;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.model.VerificationToken;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.request.LoginRequest;
import com.pdfsigner.pdf_signer.service.AuthService;
import com.pdfsigner.pdf_signer.service.EmailService;
import com.pdfsigner.pdf_signer.service.TokenService;
import com.pdfsigner.pdf_signer.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Validated
@Slf4j
public class AuthController {

        private final AuthService authService;
        private final TokenService tokenService;
        private final EmailService emailService;
        private final UserRepository userRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtUtil jwtUtil;

        // Register new user
        @PostMapping("/register")
        public ResponseEntity<ApiResponse> register(
                        @Valid @RequestBody RegisterRequest request) {

                UserDto userDto = authService.registerUser(request);

                return ResponseEntity.status(HttpStatus.CREATED)
                                .body(ApiResponse.builder()
                                                .success(true)
                                                .message("User registered successfully. Please check your email for verification.")
                                                .data(userDto)
                                                .build());
        }

        // // User login
        // @PostMapping("/login")
        // public ResponseEntity<ApiResponse> login(
        // @Valid @RequestBody LoginRequest request) {

        // LoginResponse loginResponse = authService.loginUser(request);

        // return ResponseEntity.ok(ApiResponse.builder()
        // .success(true)
        // .message("Login successful")
        // .data(loginResponse)
        // .build());
        // }

        // @PostMapping("/login")
        // public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest
        // request) {
        // LoginResponse user = authService.loginUser(request); // your validations,
        // checks, etc.

        // String accessToken = jwtUtil.generateToken(user, Duration.ofMinutes(15));
        // String refreshToken = jwtUtil.generateRefreshToken(user, Duration.ofDays(7));
        // refreshTokenService.store(user, refreshToken); // persist/rotate, tie to
        // device, etc.

        // // HttpOnly Refresh cookie (not readable by JS)
        // ResponseCookie refreshCookie = ResponseCookie.from("refresh_token",
        // refreshToken)
        // .httpOnly(true)
        // .secure(true) // true in prod (HTTPS)
        // .sameSite("Strict") // or "Lax" if you need cross-site flows
        // .path("/api/auth") // limit scope
        // .maxAge(Duration.ofDays(7))
        // .build();

        // // OPTION A (recommended): return access token in body (client keeps in
        // memory)
        // LoginResponse body = LoginResponse.builder()
        // .accessToken(accessToken)
        // .tokenType("Bearer")
        // .expiresIn(900)
        // .user(convertToDto(user))
        // .build();

        // return ResponseEntity.ok()
        // .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
        // .body(body);
        // }

        // @PostMapping("/login")
        // public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request,
        // HttpServletResponse response) {
        // LoginResponse loginResponse = authService.loginUser(request);

        // User user = loginResponse.getUser(); // convert back if needed

        // // Generate JWT for HttpOnly cookie
        // String jwtToken = jwtUtil.generateToken(user);

        // // Create HttpOnly cookie with JWT
        // ResponseCookie jwtCookie = ResponseCookie.from("jwt",
        // loginResponse.getAccessToken())
        // .httpOnly(true)
        // .secure(true) // only over HTTPS
        // .path("/") // valid for the whole API
        // .sameSite("Strict") // or "Lax"
        // .maxAge(Duration.ofSeconds(loginResponse.getExpiresIn()))
        // .build();

        // response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

        // // You can still return user info, but NOT the token
        // return ResponseEntity.ok(LoginResponse.builder()
        // .user(loginResponse.getUser())
        // .expiresIn(loginResponse.getExpiresIn())
        // .tokenType("Bearer")
        // .build());
        // }

        @PostMapping("/login")
        public ResponseEntity<LoginResponse> login(
                        @RequestBody LoginRequest request,
                        HttpServletResponse response) {

                // Validate credentials and get the User entity
                User user = authService.validateAndGetUser(request); // could be your loginUser()

                // Generate JWT for HttpOnly cookie
                String jwtToken = jwtUtil.generateToken(user);

                ResponseCookie jwtCookie = ResponseCookie.from("jwt", jwtToken)
                                .httpOnly(true)
                                .secure(true)
                                .path("/")
                                .sameSite("Strict")
                                .maxAge(Duration.ofSeconds(jwtUtil.getExpirationTimeSeconds()))
                                .build();

                response.addHeader(HttpHeaders.SET_COOKIE, jwtCookie.toString());

                // Convert User to DTO
                UserDto userDto = convertToDto(user);

                LoginResponse loginResponse = LoginResponse.builder()
                                .user(userDto)
                                .expiresIn(jwtUtil.getExpirationTimeSeconds())
                                .tokenType("Bearer")
                                .build();

                return ResponseEntity.ok(loginResponse);
        }

        // Verify email address
        @PostMapping("/verify-email")
        public ResponseEntity<ApiResponse> verifyEmail(
                        @RequestParam @NotBlank String token) {

                authService.verifyEmail(token);

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("Email verified successfully")
                                .build());
        }

        // Resend verification email
        @PostMapping("/resend-verification")
        public ResponseEntity<ApiResponse> resendVerificationEmail(
                        @RequestParam @Email @NotBlank String email) {

                VerificationToken newToken = tokenService.resendVerificationToken(email);
                User user = newToken.getUser();
                emailService.sendVerificationEmail(user, newToken.getToken());

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("Verification email resent successfully")
                                .build());
        }

        // Forgot password - request password reset
        @PostMapping("/forgot-password")
        public ResponseEntity<ApiResponse> forgotPassword(
                        @RequestParam @Email @NotBlank String email) {

                User user = userRepository.findByEmail(email)
                                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

                VerificationToken resetToken = tokenService.createPasswordResetToken(user);
                emailService.sendPasswordResetEmail(user, resetToken.getToken());

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("Password reset email sent successfully")
                                .build());
        }

        // Reset password with token
        @PostMapping("/reset-password")
        public ResponseEntity<ApiResponse> resetPassword(
                        @RequestParam @NotBlank String token,
                        @Valid @RequestBody ResetPasswordRequest request) {

                request.validate(); // Validate password confirmation

                VerificationToken resetToken = tokenService.validateToken(token, TokenType.PASSWORD_RESET);
                User user = resetToken.getUser();

                user.setPassword(passwordEncoder.encode(request.getNewPassword()));
                userRepository.save(user);

                tokenService.useToken(resetToken);

                // Log password change
                // Note: You'll need to inject AuditService for this
                // auditService.logPasswordChange(user);

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("Password reset successfully")
                                .build());
        }

        // Get current user profile
        @GetMapping("/me")
        public ResponseEntity<ApiResponse> getCurrentUser(
                        @AuthenticationPrincipal UserDetails userDetails) {

                User user = userRepository.findByEmail(userDetails.getUsername())
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                UserDto userDto = convertToDto(user);

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("User profile retrieved successfully")
                                .data(userDto)
                                .build());
        }

        // Update user profile
        @PutMapping("/profile")
        public ResponseEntity<ApiResponse> updateProfile(
                        @AuthenticationPrincipal UserDetails userDetails,
                        @Valid @RequestBody UpdateProfileRequest request) {

                User user = userRepository.findByEmail(userDetails.getUsername())
                                .orElseThrow(() -> new UserNotFoundException("User not found"));

                user.setUsername(request.getUsername());
                User updatedUser = userRepository.save(user);

                UserDto userDto = convertToDto(updatedUser);

                return ResponseEntity.ok(ApiResponse.builder()
                                .success(true)
                                .message("Profile updated successfully")
                                .data(userDto)
                                .build());
        }

        // Exception handling
        @ExceptionHandler({
                        EmailAlreadyExistsException.class,
                        UsernameAlreadyExistsException.class,
                        InvalidTokenException.class,
                        TokenExpiredException.class,
                        UserNotFoundException.class,
                        UserAlreadyVerifiedException.class
        })
        public ResponseEntity<ApiResponse> handleCustomExceptions(RuntimeException ex) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.builder()
                                                .success(false)
                                                .message(ex.getMessage())
                                                .build());
        }

        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ApiResponse> handleValidationExceptions(MethodArgumentNotValidException ex) {
                List<String> errors = ex.getBindingResult()
                                .getFieldErrors()
                                .stream()
                                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                .collect(Collectors.toList());

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.builder()
                                                .success(false)
                                                .message("Validation failed")
                                                .data(errors)
                                                .build());
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<ApiResponse> handleGeneralExceptions(Exception ex) {
                log.error("Unexpected error occurred: ", ex);

                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.builder()
                                                .success(false)
                                                .message("An unexpected error occurred")
                                                .build());
        }

        // Helper method to convert User to UserDto
        private UserDto convertToDto(User user) {
                return UserDto.builder()
                                .id(user.getId())
                                .email(user.getEmail())
                                .username(user.getUsername())
                                .roles(user.getRoles().stream()
                                                .map(Role::name)
                                                .collect(Collectors.toSet()))
                                .createdAt(user.getCreatedAt())
                                .enabled(user.isEnabled())
                                .build();
        }

        @PostMapping("/logout")
        public ResponseEntity<Void> logout(HttpServletRequest request) {
                // cookieUtil.read(request,
                // "refresh_token").ifPresent(refreshTokenService::revoke);

                ResponseCookie clearRefresh = ResponseCookie.from("refresh_token", "")
                                .httpOnly(true).secure(true).sameSite("Strict").path("/api/auth")
                                .maxAge(0).build();

                return ResponseEntity.noContent()
                                .header(HttpHeaders.SET_COOKIE, clearRefresh.toString())
                                .build();
        }

}
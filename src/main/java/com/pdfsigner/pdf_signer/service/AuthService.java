package com.pdfsigner.pdf_signer.service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.pdfsigner.pdf_signer.dto.LoginResponse;
import com.pdfsigner.pdf_signer.dto.RegisterRequest;
import com.pdfsigner.pdf_signer.dto.UserDto;
import com.pdfsigner.pdf_signer.dto.UserLoggedInEvent;
import com.pdfsigner.pdf_signer.excetion.AccountLockedException;
import com.pdfsigner.pdf_signer.excetion.AccountNotVerifiedException;
import com.pdfsigner.pdf_signer.excetion.EmailAlreadyExistsException;
import com.pdfsigner.pdf_signer.excetion.InvalidEmailException;
import com.pdfsigner.pdf_signer.excetion.InvalidPasswordException;
import com.pdfsigner.pdf_signer.excetion.InvalidUsernameException;
import com.pdfsigner.pdf_signer.excetion.UserAlreadyVerifiedException;
import com.pdfsigner.pdf_signer.model.Role;
import com.pdfsigner.pdf_signer.model.TokenType;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.model.VerificationToken;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.request.LoginRequest;
import com.pdfsigner.pdf_signer.util.JwtUtil;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final ApplicationEventPublisher eventPublisher;
    private final JwtUtil jwtUtil;

    @Transactional
    public UserDto registerUser(RegisterRequest request) {
        validateRegistrationRequest(request);

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists");
        }

        User user = createUserFromRequest(request);
        // user.setEnabled(false); // Must verify email first
        // user.setAccountNonLocked(true);
        // user.setCredentialsNonExpired(true); // ← ADD THIS LINE

        User savedUser = userRepository.save(user);

        // Create and send verification token
        VerificationToken verificationToken = tokenService.createEmailVerificationToken(savedUser);
        emailService.sendVerificationEmail(savedUser, verificationToken.getToken());

        log.info("User registered successfully. Verification email sent to: {}", savedUser.getEmail());

        return convertToDto(savedUser);
    }

    // Email verification endpoint
    @Transactional
    public void verifyEmail(String token) {
        VerificationToken verificationToken = tokenService.validateToken(token, TokenType.EMAIL_VERIFICATION);

        User user = verificationToken.getUser();
        if (user.isEnabled()) {
            throw new UserAlreadyVerifiedException("Email is already verified");
        }

        user.setEnabled(true);
        userRepository.save(user);

        tokenService.useToken(verificationToken);
        log.info("Email verified successfully for user: {}", user.getEmail());

        // Send welcome email after verification
        eventPublisher.publishEvent(new UserVerifiedEvent(user));
    }

    private void validateRegistrationRequest(RegisterRequest request) {
        if (request.getPassword().length() < 8) {
            throw new InvalidPasswordException("Password must be at least 8 characters");
        }

        if (!isValidEmail(request.getEmail())) {
            throw new InvalidEmailException("Invalid email format");
        }

        if (request.getUsername().length() < 3) {
            throw new InvalidUsernameException("Username must be at least 3 characters");
        }
    }

    private User createUserFromRequest(RegisterRequest request) {
        return User.builder()
                .username(request.getUsername().trim())
                .email(request.getEmail().toLowerCase().trim())
                .password(passwordEncoder.encode(request.getPassword()))
                .createdAt(LocalDateTime.now())
                .lastLoginAt(null)
                .enabled(false)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(Role.USER))
                .build();
    }

    private String generateVerificationToken() {
        return UUID.randomUUID().toString();
    }

    private UserDto convertToDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .username(user.getUsername())
                .roles(user.getRoles().stream()
                        .map(Role::name)
                        .collect(Collectors.toSet()))
                .createdAt(user.getCreatedAt())
                .build();
    }

    // Additional validation method
    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
        return Pattern.compile(emailRegex).matcher(email).matches();
    }

    // ... The logging part right here ...

    @Transactional
    public LoginResponse loginUser(LoginRequest request) {
        log.info("Login attempt for email: {}", request.getEmail());

        // Validate input
        validateLoginRequest(request);

        // Find user by email
        User user = userRepository.findByEmailWithRoles(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Check if account is enabled
        if (!user.isEnabled()) {
            throw new AccountNotVerifiedException("Please verify your email address before logging in");
        }

        // Check if account is locked
        if (!user.isAccountNonLocked()) {
            throw new AccountLockedException("Account is locked. Please contact support");
        }

        // Check if credentials are still valid
        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("Your password has expired. Please reset it");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            handleFailedLoginAttempt(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        // Successful login - update user and generate token
        return processSuccessfulLogin(user, request);
    }

    @Transactional
    public User validateAndGetUser(LoginRequest request) {
        log.info("Login attempt for email: {}", request.getEmail());

        // Validate input
        validateLoginRequest(request);

        // Find user by email
        User user = userRepository.findByEmailWithRoles(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        // Check if account is enabled
        if (!user.isEnabled()) {
            throw new AccountNotVerifiedException("Please verify your email address before logging in");
        }

        // Check if account is locked
        if (!user.isAccountNonLocked()) {
            throw new AccountLockedException("Account is locked. Please contact support");
        }

        // Check if credentials are still valid
        if (!user.isCredentialsNonExpired()) {
            throw new CredentialsExpiredException("Your password has expired. Please reset it");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            handleFailedLoginAttempt(user);
            throw new BadCredentialsException("Invalid email or password");
        }

        // Update last login time
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        return user; // Return the User entity for token generation
    }

    private void validateLoginRequest(LoginRequest request) {
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }

        if (request.getPassword() == null || request.getPassword().trim().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }

        if (!isValidEmail(request.getEmail())) {
            throw new InvalidEmailException("Invalid email format");
        }
    }

    private void handleFailedLoginAttempt(User user) {
        // Increment failed login attempts
        // You might want to add a failedAttempts field to your User entity
        // and implement account locking after too many failed attempts

        log.warn("Failed login attempt for user: {}", user.getEmail());
        auditService.logSecurityEvent("FAILED_LOGIN_ATTEMPT",
                "Failed login attempt for user: " + user.getEmail(), user);
    }

    @Transactional
    private LoginResponse processSuccessfulLogin(User user, LoginRequest request) {
        // Update last login time
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWT token
        String accessToken = jwtUtil.generateToken(user);

        // Log successful login
        auditService.logLogin(user);
        log.info("User logged in successfully: {}", user.getEmail());

        // Publish login event for async processing (analytics, notifications, etc.)
        eventPublisher.publishEvent(new UserLoggedInEvent(user, getClientIpAddress(), getUserAgent()));

        return buildLoginResponse(user, accessToken);
    }

    private LoginResponse buildLoginResponse(User user, String accessToken) {
        return LoginResponse.builder()
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getExpirationTimeSeconds()) // e.g., 3600 seconds
                .user(convertToDto(user))
                .build();
    }

    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                return getClientIpFromRequest(request);
            }
        } catch (Exception e) {
            log.warn("Could not get client IP address", e);
        }
        return "unknown";
    }

    // @Transactional
    // private LoginResponse processSuccessfulLogin(User user, LoginRequest request)
    // {
    // // Update last login time
    // user.setLastLoginAt(LocalDateTime.now());
    // userRepository.save(user);

    // // Generate short-lived access token
    // String accessToken = jwtUtil.generateToken(user, Duration.ofMinutes(15));

    // // Generate refresh token (store in DB so it can be revoked)
    // String refreshToken = jwtUtil.generateRefreshToken(user, Duration.ofDays(7));
    // refreshTokenRepository.save(new RefreshToken(user, refreshToken,
    // LocalDateTime.now().plusDays(7)));

    // // Audit log (IP, user-agent, timestamp)
    // auditService.logLogin(user, getClientIpAddress(), getUserAgent());

    // // Publish async login event
    // eventPublisher.publishEvent(new UserLoggedInEvent(user, getClientIpAddress(),
    // getUserAgent()));

    // // Build secure response
    // return LoginResponse.builder()
    // .accessToken(accessToken)
    // .refreshToken(refreshToken)
    // .expiresIn(900) // 15 minutes
    // .userId(user.getId())
    // .email(user.getEmail())
    // .roles(user.getRoles().stream().map(Enum::name).toList())
    // .build();
    // }

    private String getClientIpFromRequest(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }

    private String getUserAgent() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                return attributes.getRequest().getHeader("User-Agent");
            }
        } catch (Exception e) {
            log.warn("Could not get user agent", e);
        }
        return "unknown";
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        VerificationToken resetToken = tokenService.validateToken(token, TokenType.PASSWORD_RESET);
        User user = resetToken.getUser();

        // Set the new password
        user.setPassword(passwordEncoder.encode(newPassword));

        // CRITICAL: Enable the user account if it was disabled
        user.setEnabled(true);
        user.setAccountNonLocked(true);
        user.setCredentialsNonExpired(true); // ← ADD THIS LINE

        userRepository.save(user);
        tokenService.useToken(resetToken);

        log.info("Password reset successfully for user: {}", user.getEmail());

        // Send confirmation email
        emailService.sendPasswordResetConfirmationEmail(user);
    }
}
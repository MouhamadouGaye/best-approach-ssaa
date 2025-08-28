package com.pdfsigner.pdf_signer.service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.pdfsigner.pdf_signer.excetion.InvalidTokenException;
import com.pdfsigner.pdf_signer.excetion.TokenAlreadyUsedException;
import com.pdfsigner.pdf_signer.excetion.TokenExpiredException;
import com.pdfsigner.pdf_signer.excetion.UserAlreadyVerifiedException;
import com.pdfsigner.pdf_signer.excetion.UserNotFoundException;
import com.pdfsigner.pdf_signer.model.TokenType;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.model.VerificationToken;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.repository.VerificationTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class TokenService {

    private final VerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private static final String SAFE_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final int TOKEN_LENGTH = 40;

    // Email Verification
    public VerificationToken createEmailVerificationToken(User user) {
        return createToken(user, TokenType.EMAIL_VERIFICATION, 24); // 24 hours expiry
    }

    // Password Reset
    public VerificationToken createPasswordResetToken(User user) {
        return createToken(user, TokenType.PASSWORD_RESET, 1); // 1 hour expiry
    }

    // Account Unlock
    public VerificationToken createAccountUnlockToken(User user) {
        return createToken(user, TokenType.ACCOUNT_UNLOCK, 24);
    }

    private VerificationToken createToken(User user, TokenType tokenType, int expiryHours) {
        // Delete any existing tokens of same type for this user
        tokenRepository.findByUserAndTokenType(user, tokenType)
                .ifPresent(tokenRepository::delete);

        String tokenValue = generateSecureToken();

        VerificationToken token = VerificationToken.builder()
                .token(tokenValue)
                .user(user)
                .tokenType(tokenType)
                .expiryDate(LocalDateTime.now().plusHours(expiryHours))
                .build();

        return tokenRepository.save(token);
    }

    // SAFE_CHARACTERS="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // System.out.println(SAFE_CHARACTERS.charAt(34));

    public String generateSecureToken() {
        SecureRandom random = new SecureRandom();
        StringBuilder token = new StringBuilder(TOKEN_LENGTH);

        for (int i = 0; i < TOKEN_LENGTH; i++) {
            token.append(SAFE_CHARACTERS.charAt(random.nextInt(SAFE_CHARACTERS.length())));
        }

        String generatedToken = token.toString();
        log.info("Generated safe token: {}", generatedToken);
        return generatedToken;
    }

    // public VerificationToken validateToken(String tokenValue, TokenType
    // expectedType) {
    // VerificationToken token = tokenRepository.findByTokenAndTokenType(tokenValue,
    // expectedType)
    // .orElseThrow(() -> new InvalidTokenException("Invalid or expired token"));

    // if (token.isUsed()) {
    // throw new TokenAlreadyUsedException("Token has already been used");
    // }

    // if (token.isExpired()) {
    // tokenRepository.delete(token);
    // throw new TokenExpiredException("Token has expired");
    // }

    // return token;
    // }

    public VerificationToken validateToken(String tokenValue, TokenType expectedType) {
        log.info("Validating token: {}, type: {}", tokenValue, expectedType);

        try {
            VerificationToken token = tokenRepository.findByTokenAndTokenType(tokenValue,
                    expectedType)
                    .orElseThrow(() -> {
                        log.warn("Token not found: {}", tokenValue);
                        return new InvalidTokenException("Invalid or expired token");
                    });

            log.info("Token found: {}, expired: {}, used: {}", tokenValue,
                    token.isExpired(), token.isUsed());

            if (token.isUsed()) {
                log.warn("Token already used: {}", tokenValue);
                throw new TokenAlreadyUsedException("Token has already been used");
            }

            if (token.isExpired()) {
                log.warn("Token expired: {}", tokenValue);
                throw new TokenExpiredException("Token has expired");
            }

            return token;

        } catch (Exception e) {
            log.error("Token validation failed for token: {}", tokenValue, e);
            throw e;
        }
    }

    public void useToken(VerificationToken token) {
        token.markAsUsed();
        tokenRepository.save(token);
    }

    public void deleteToken(VerificationToken token) {
        tokenRepository.delete(token);
    }

    // Cleanup expired tokens (can be scheduled)
    @Scheduled(cron = "0 0 2 * * ?") // Run daily at 2 AM
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        int deletedCount = tokenRepository.deleteByExpiryDateBefore(now);
        log.info("Cleaned up {} expired tokens", deletedCount);
    }

    // Resend verification email
    public VerificationToken resendVerificationToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

        if (user.isEnabled()) {
            throw new UserAlreadyVerifiedException("User is already verified");
        }

        return createEmailVerificationToken(user);
    }
}
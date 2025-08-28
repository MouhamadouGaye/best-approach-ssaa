package com.pdfsigner.pdf_signer.service;

import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import com.pdfsigner.pdf_signer.model.User;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserRegistrationListener {

    private final EmailService emailService;
    private final AuditService auditService;
    private final AnalyticsService analyticsService; // Optional: for analytics

    @Async
    @EventListener
    public void handleUserRegisteredEvent(UserRegisteredEvent event) {
        try {
            User user = event.getUser();

            // Send welcome email
            emailService.sendWelcomeEmail(user);

            // Log registration in audit trail
            auditService.logRegistration(user);

            // Send to analytics (optional)
            analyticsService.trackRegistration(user);

            log.info("Async registration tasks completed for user: {}", user.getEmail());

        } catch (Exception e) {
            log.error("Failed to process user registration event for user: {}",
                    event.getUser().getEmail(), e);
        }
    }

    @Async
    @EventListener
    public void handleUserVerifiedEvent(UserVerifiedEvent event) {
        try {
            User user = event.getUser();

            // Log email verification
            auditService.logEmailVerification(user);

            // Send post-verification email
            emailService.sendPostVerificationEmail(user);

            log.info("Async verification tasks completed for user: {}", user.getEmail());

        } catch (Exception e) {
            log.error("Failed to process user verification event for user: {}",
                    event.getUser().getEmail(), e);
        }
    }
}
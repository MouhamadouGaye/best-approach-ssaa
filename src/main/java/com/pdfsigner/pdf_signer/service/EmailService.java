package com.pdfsigner.pdf_signer.service;

import com.pdfsigner.pdf_signer.model.User;

public interface EmailService {
    void sendWelcomeEmail(User user);

    void sendEmail(String to, String subject, String content, boolean isHtml);

    void sendVerificationEmail(User user, String verificationToken);

    void sendPasswordResetEmail(User user, String resetToken);

    void sendPostVerificationEmail(User user);

    void sendPasswordResetConfirmationEmail(User user);
}
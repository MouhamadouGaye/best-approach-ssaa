package com.pdfsigner.pdf_signer.service.impl;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.pdfsigner.pdf_signer.excetion.EmailSendingException;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.service.EmailService;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine; // For Thymeleaf templates
    private final Environment env;

    @Override
    public void sendWelcomeEmail(User user) {
        String subject = "Welcome to Our Application!";

        Map<String, Object> variables = new HashMap<>();
        variables.put("user", user);
        variables.put("applicationName", env.getProperty("app.name", "Our Application"));

        String htmlContent = processTemplate("emails/welcome-email", variables);

        sendEmail(user.getEmail(), subject, htmlContent, true);
    }

    @Override
    public void sendVerificationEmail(User user, String verificationToken) {
        String subject = "Verify Your Email Address";
        String verificationUrl = env.getProperty("app.base-url") + "/api/verification/verify-email?token="
                + verificationToken;

        Map<String, Object> variables = new HashMap<>();
        variables.put("user", user);
        variables.put("verificationUrl", verificationUrl);
        variables.put("expirationHours", 24);

        String htmlContent = processTemplate("emails/verification-email", variables);

        sendEmail(user.getEmail(), subject, htmlContent, true);
    }

    @Override
    public void sendPasswordResetEmail(User user, String resetToken) {
        String subject = "Password Reset Request";
        String resetUrl = env.getProperty("app.base-url") + "/api/verification/reset-password?token=" + resetToken;

        Map<String, Object> variables = new HashMap<>();
        variables.put("user", user);
        variables.put("resetUrl", resetUrl);
        variables.put("expirationHours", 1);

        String htmlContent = processTemplate("emails/password-reset-email", variables);

        sendEmail(user.getEmail(), subject, htmlContent, true);
    }

    @Override
    public void sendEmail(String to, String subject, String content, boolean isHtml) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(content, isHtml);
            helper.setFrom(env.getProperty("spring.mail.from", "noreply@yourapp.com"));

            mailSender.send(message);
            log.info("Email sent successfully to: {}", to);

        } catch (MessagingException e) {
            log.error("Failed to send email to: {}", to, e);
            throw new EmailSendingException("Failed to send email to: " + to, e);
        }
    }

    private String processTemplate(String templateName, Map<String, Object> variables) {
        Context context = new Context();
        context.setVariables(variables);

        return templateEngine.process(templateName, context);
    }

    @Override
    public void sendPostVerificationEmail(User user) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            Context context = new Context();
            context.setVariable("user", user);
            context.setVariable("supportEmail", "support@yourdomain.com");

            String htmlContent = templateEngine.process("emails/welcome-email", context);

            helper.setTo(user.getEmail());
            helper.setFrom(env.getProperty("spring.mail.username"));
            helper.setSubject("Welcome to Our Platform!");
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Post-verification welcome email sent to: {}", user.getEmail());

        } catch (Exception e) {
            log.error("Failed to send post-verification email to: {}", user.getEmail(), e);
            throw new EmailSendingException("Failed to send welcome email", e);
        }
    }

    @Override
    public void sendPasswordResetConfirmationEmail(User user) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            Context context = new Context();
            context.setVariable("user", user);
            context.setVariable("timestamp", LocalDateTime.now());

            String htmlContent = templateEngine.process("email/password-reset-confirmation", context);

            helper.setTo(user.getEmail());
            helper.setFrom(env.getProperty("spring.mail.username"));
            helper.setSubject("Password Reset Successful - PDF Signer");
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Password reset confirmation email sent to: {}", user.getEmail());

        } catch (Exception e) {
            log.error("Failed to send password reset confirmation email to: {}", user.getEmail(), e);
        }
    }
}
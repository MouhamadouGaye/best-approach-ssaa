// package com.pdfsigner.pdf_signer.service.impl;

// import org.hibernate.cfg.Environment;
// import org.springframework.mail.javamail.JavaMailSender;
// import org.springframework.stereotype.Service;
// import org.thymeleaf.TemplateEngine;

// import com.pdfsigner.pdf_signer.service.EmailService;

// import lombok.RequiredArgsConstructor;
// import lombok.extern.slf4j.Slf4j;

// @Service
// @Slf4j
// @RequiredArgsConstructor
// public class EmailServiceImpl2 implements EmailService {

// private final JavaMailSender mailSender;
// private final TemplateEngine templateEngine; // If using Thymeleaf
// private final Environment env;

// @Override
// public void sendVerificationEmail(User user, String token) {
// // Your existing implementation
// }

// @Override
// public void sendPostVerificationEmail(User user) {
// try {
// MimeMessage message = mailSender.createMimeMessage();
// MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

// String subject = "Welcome to Our Platform!";
// String from = env.getProperty("spring.mail.username",
// "noreply@yourdomain.com");

// helper.setTo(user.getEmail());
// helper.setFrom(from);
// helper.setSubject(subject);

// // Create email content
// String content = buildPostVerificationEmailContent(user);
// helper.setText(content, true); // true = HTML content

// mailSender.send(message);
// log.info("Post-verification welcome email sent to: {}", user.getEmail());

// } catch (Exception e) {
// log.error("Failed to send post-verification email to: {}", user.getEmail(),
// e);
// throw new EmailSendingException("Failed to send welcome email", e);
// }
// }

// private String buildPostVerificationEmailContent(User user) {
// // Simple version - you can use Thymeleaf templates for a better look
// return """
// <!DOCTYPE html>
// <html>
// <head>
// <meta charset="UTF-8">
// <title>Welcome!</title>
// </head>
// <body>
// <h2>Welcome to Our Platform, %s!</h2>
// <p>Your email has been successfully verified.</p>
// <p>You can now enjoy all the features of our platform.</p>
// <br>
// <p>Best regards,<br>The Team</p>
// </body>
// </html>
// """.formatted(user.getUsername());
// }

// // Optional: Create a custom exception
// public class EmailSendingException extends RuntimeException {
// public EmailSendingException(String message, Throwable cause) {
// super(message, cause);
// }
// }
// }
package com.pdfsigner.pdf_signer.service;

import com.pdfsigner.pdf_signer.model.User;

public interface AuditService {
    void logRegistration(User user);

    void logLogin(User user);

    void logLogout(User user);

    void logPasswordChange(User user);

    void logEmailVerification(User user);

    void logSecurityEvent(String eventType, String description, User user);

    void logActivity(String activity, User user);
}
package com.pdfsigner.pdf_signer.service.impl;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pdfsigner.pdf_signer.model.AuditLog;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.AuditLogRepository;
import com.pdfsigner.pdf_signer.service.AuditService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuditServiceImpl implements AuditService {

    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper;

    @Override
    @Async
    public void logRegistration(User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("USER_REGISTRATION")
                .description("User registered successfully")
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, null))
                .build();

        auditLogRepository.save(auditLog);
        log.info("Registration logged for user: {}", user.getEmail());
    }

    @Override
    @Async
    public void logLogin(User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("USER_LOGIN")
                .description("User logged in successfully")
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, Map.of("loginTime", LocalDateTime.now())))
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    @Async
    public void logLogout(User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("USER_LOGOUT")
                .description("User logged out")
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, null))
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    @Async
    public void logPasswordChange(User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("PASSWORD_CHANGE")
                .description("User changed password")
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, Map.of("changeTime", LocalDateTime.now())))
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    @Async
    public void logEmailVerification(User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("EMAIL_VERIFICATION")
                .description("User verified email address")
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, Map.of("verificationTime", LocalDateTime.now())))
                .build();

        auditLogRepository.save(auditLog);
    }

    @Override
    @Async
    public void logSecurityEvent(String eventType, String description, User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType(eventType)
                .description(description)
                .userId(user != null ? user.getId() : null)
                .username(user != null ? user.getUsername() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, null))
                .build();

        auditLogRepository.save(auditLog);
        log.warn("Security event: {} - {}", eventType, description);
    }

    @Override
    @Async
    public void logActivity(String activity, User user) {
        AuditLog auditLog = AuditLog.builder()
                .eventType("USER_ACTIVITY")
                .description(activity)
                .userId(user.getId())
                .username(user.getUsername())
                .userEmail(user.getEmail())
                .ipAddress(getClientIpAddress())
                .userAgent(getUserAgent())
                .metadata(createMetadata(user, Map.of("activity", activity)))
                .build();

        auditLogRepository.save(auditLog);
    }

    private String createMetadata(User user, Map<String, Object> additionalData) {
        try {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("timestamp", LocalDateTime.now());
            metadata.put("userAgent", getUserAgent());
            metadata.put("ipAddress", getClientIpAddress());

            if (user != null) {
                metadata.put("userId", user.getId());
                metadata.put("userEmail", user.getEmail());
                metadata.put("username", user.getUsername());
            }

            if (additionalData != null) {
                metadata.putAll(additionalData);
            }

            return objectMapper.writeValueAsString(metadata);
        } catch (JsonProcessingException e) {
            log.error("Failed to create audit metadata", e);
            return "{}";
        }
    }

    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
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
        } catch (Exception e) {
            log.warn("Could not get client IP address", e);
        }
        return "unknown";
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
}
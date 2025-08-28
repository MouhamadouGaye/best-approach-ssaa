package com.pdfsigner.pdf_signer.service;

import java.util.Map;

import org.springframework.stereotype.Service;

import com.pdfsigner.pdf_signer.model.User;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AnalyticsService {

    public void trackRegistration(User user) {
        // Implement your analytics tracking here
        // This could be Google Analytics, Mixpanel, Amplitude, etc.
        log.info("Tracking registration for user: {}", user.getEmail());
    }

    public void trackLogin(User user) {
        log.info("Tracking login for user: {}", user.getEmail());
    }

    public void trackEvent(String eventName, User user, Map<String, Object> properties) {
        log.info("Tracking event '{}' for user: {} with properties: {}",
                eventName, user.getEmail(), properties);
    }
}
package com.pdfsigner.pdf_signer.dto;

import com.pdfsigner.pdf_signer.model.User;

public class UserLoggedInEvent {
    private final User user;
    private final String ipAddress;
    private final String userAgent;

    public UserLoggedInEvent(User user, String ipAddress, String userAgent) {
        this.user = user;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }

    public User getUser() {
        return user;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }
}
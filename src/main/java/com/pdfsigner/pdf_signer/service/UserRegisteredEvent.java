package com.pdfsigner.pdf_signer.service;

import com.pdfsigner.pdf_signer.model.User;

public class UserRegisteredEvent {
    private final User user;

    public UserRegisteredEvent(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}

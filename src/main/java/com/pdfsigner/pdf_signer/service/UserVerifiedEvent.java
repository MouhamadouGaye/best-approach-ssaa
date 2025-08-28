package com.pdfsigner.pdf_signer.service;

import com.pdfsigner.pdf_signer.model.User;

public class UserVerifiedEvent {
    private final User user;

    public UserVerifiedEvent(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}
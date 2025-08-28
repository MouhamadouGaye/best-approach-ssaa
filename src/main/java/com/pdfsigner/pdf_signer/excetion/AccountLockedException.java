package com.pdfsigner.pdf_signer.excetion;

public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) {
        super(message);
    }
}

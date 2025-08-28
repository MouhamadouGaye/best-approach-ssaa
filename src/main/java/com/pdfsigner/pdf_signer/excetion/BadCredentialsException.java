package com.pdfsigner.pdf_signer.excetion;

public class BadCredentialsException extends RuntimeException {
    public BadCredentialsException(String message) {
        super(message);
    }
}
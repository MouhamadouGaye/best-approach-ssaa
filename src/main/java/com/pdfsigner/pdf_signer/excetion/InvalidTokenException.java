package com.pdfsigner.pdf_signer.excetion;

public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}

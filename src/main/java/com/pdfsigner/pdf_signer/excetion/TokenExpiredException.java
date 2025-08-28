package com.pdfsigner.pdf_signer.excetion;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }
}
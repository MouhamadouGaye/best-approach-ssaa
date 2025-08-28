package com.pdfsigner.pdf_signer.excetion;

public class InvalidEmailException extends RuntimeException {
    public InvalidEmailException(String message) {
        super(message);
    }
}
package com.pdfsigner.pdf_signer.dto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class AuthResponse {
    private String token;
    private UserDto user;
    // getters and setters

    public AuthResponse(String token, UserDto user) {
        this.token = token;
        this.user = user;
    }

}

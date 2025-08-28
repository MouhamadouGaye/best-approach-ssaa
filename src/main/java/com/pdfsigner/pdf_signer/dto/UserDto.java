package com.pdfsigner.pdf_signer.dto;

import java.time.LocalDateTime;
import java.util.Set;

import com.pdfsigner.pdf_signer.model.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String email;
    private String username;
    private Set<String> roles;
    private LocalDateTime createdAt;
    private boolean enabled;
    private LocalDateTime lastLoginAt;
}
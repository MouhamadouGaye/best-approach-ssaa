package com.pdfsigner.pdf_signer.dto;

import java.util.Set;

import javax.management.relation.Role;

import com.pdfsigner.pdf_signer.excetion.InvalidPasswordException;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    // @NotBlank
    // private String username;

    // @Email
    // @NotBlank
    // private String email;

    // @NotBlank
    // @Size(min = 8)
    // private String password;

    // // Must have default constructor
    // public RegisterRequest() {
    // }

    // // Getters and Setters
    // public String getUsername() {
    // return username;
    // }

    // public void setUsername(String username) {
    // this.username = username;
    // }

    // public String getPassword() {
    // return password;
    // }

    // public void setPassword(String password) {
    // this.password = password;
    // }

    // public String getEmail() {
    // return email;
    // }

    // public void setEmail(String email) {
    // this.email = email;
    // }

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$", message = "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character")
    private String password;

    // Custom validation method
    public void validate() {
        if (password != null && password.contains(username)) {
            throw new InvalidPasswordException("Password cannot contain username");
        }
    }
}
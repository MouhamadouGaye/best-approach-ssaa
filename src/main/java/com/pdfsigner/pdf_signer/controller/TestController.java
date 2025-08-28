package com.pdfsigner.pdf_signer.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pdfsigner.pdf_signer.service.TokenService;

@RestController
@RequestMapping("/api/test")
public class TestController {

    private final TokenService tokenService;

    public TestController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/generate-tokens")
    public ResponseEntity<String> generateTestTokens() {
        StringBuilder result = new StringBuilder();
        result.append("<h1>Test Token Generation</h1>");
        result.append("<pre>");

        for (int i = 0; i < 10; i++) {
            String token = tokenService.generateSecureToken();
            result.append("Token ").append(i + 1).append(": ").append(token).append("\n");
            result.append("URL: http://localhost:8080/api/verification/reset-password?token=").append(token)
                    .append("\n\n");
        }

        result.append("</pre>");
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(result.toString());
    }
}
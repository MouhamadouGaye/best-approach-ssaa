package com.pdfsigner.pdf_signer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import com.pdfsigner.pdf_signer.model.Signature;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.service.SignatureService;
import com.pdfsigner.pdf_signer.service.UserService;

import lombok.RequiredArgsConstructor;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/signatures")
public class SignatureController {

    private final SignatureService signatureService;
    private final UserService userService;

    @PostMapping
    public ResponseEntity<?> saveSignature(
            @RequestBody Map<String, String> request,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            User user = userService.getUserByUsername(userDetails.getUsername());
            Signature signature = signatureService.saveSignature(request.get("signatureData"), user);
            return ResponseEntity.ok(signature);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping
    public ResponseEntity<?> getUserSignatures(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            User user = userService.getUserByUsername(userDetails.getUsername());
            List<Signature> signatures = signatureService.getUserSignatures(user);
            return ResponseEntity.ok(signatures);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getSignature(@PathVariable Long id) {
        try {
            Signature signature = signatureService.getSignature(id);
            String base64Data = Base64.getEncoder().encodeToString(signature.getSignatureData());

            return ResponseEntity.ok()
                    .contentType(MediaType.IMAGE_PNG)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"signature_" + id + ".png\"")
                    .body(signature.getSignatureData());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}

package com.pdfsigner.pdf_signer.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.pdfsigner.pdf_signer.model.Signature;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.SignatureRepository;

import lombok.RequiredArgsConstructor;

// import java.security.Signature;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;

@RequiredArgsConstructor
@Service
public class SignatureService {

    private final SignatureRepository signatureRepository;

    public Signature saveSignature(String signatureBase64Data, User user) {
        // Remove data:image/png;base64, prefix if present
        String cleanBase64 = signatureBase64Data;
        if (signatureBase64Data.contains(",")) {
            cleanBase64 = signatureBase64Data.split(",")[1];
        }

        byte[] signatureData = Base64.getDecoder().decode(cleanBase64);

        Signature signature = new Signature();
        signature.setUser(user);
        signature.setSignatureData(signatureData);
        signature.setCreatedAt(LocalDateTime.now());

        return signatureRepository.save(signature);
    }

    public List<Signature> getUserSignatures(User user) {
        return signatureRepository.findByUserOrderByCreatedAtDesc(user);
    }

    public Signature getSignature(Long id) {
        return signatureRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Signature not found"));
    }
}

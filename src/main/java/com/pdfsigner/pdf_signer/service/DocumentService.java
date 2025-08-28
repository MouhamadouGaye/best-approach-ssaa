package com.pdfsigner.pdf_signer.service;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.pdfsigner.pdf_signer.model.Document;
import com.pdfsigner.pdf_signer.model.Status;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.DocumentRepository;

import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DocumentService {

    private final DocumentRepository documentRepository;

    public Document uploadDocument(MultipartFile file, User user) throws IOException {
        Document document = new Document();
        document.setFilename(file.getOriginalFilename());
        document.setOriginalFile(file.getBytes());
        document.setUploadedBy(user);
        document.setStatus(Status.UPLOADED);
        document.setUploadedAt(LocalDateTime.now());

        return documentRepository.save(document);
    }

    public Document getDocument(Long id) {
        return documentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Document not found"));
    }

    public List<Document> getUserDocuments(User user) {
        return documentRepository.findByUploadedByOrderByUploadedAtDesc(user);
    }

    public Document signDocument(Long id, byte[] signedPdf) {
        Document document = getDocument(id);
        document.setSignedFile(signedPdf);
        document.setStatus(Status.SIGNED);
        document.setSignedAt(LocalDateTime.now());

        return documentRepository.save(document);
    }
}

package com.pdfsigner.pdf_signer.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.pdfsigner.pdf_signer.model.Document;

import com.pdfsigner.pdf_signer.model.User;

import java.util.List;

@Repository
public interface DocumentRepository extends JpaRepository<Document, Long> {
    List<Document> findByUploadedBy(User user);

    List<Document> findByUploadedByOrderByUploadedAtDesc(User user);
}

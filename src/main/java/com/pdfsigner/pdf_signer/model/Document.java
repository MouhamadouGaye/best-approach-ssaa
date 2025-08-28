package com.pdfsigner.pdf_signer.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "documents")
public class Document {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String filename;

    @Lob
    @Column(name = "original_file", nullable = false)
    private byte[] originalFile;

    @Lob
    @Column(name = "signed_file")
    private byte[] signedFile;

    @ManyToOne
    @JoinColumn(name = "uploaded_by")
    private User uploadedBy;

    @Enumerated(EnumType.STRING) // ← This is the key annotation
    @Column(length = 20) // Optional but recommended for database schema
    private Status status;

    @Column(name = "uploaded_at")
    private LocalDateTime uploadedAt;

    @Column(name = "signed_at")
    private LocalDateTime signedAt;

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public byte[] getOriginalFile() {
        return originalFile;
    }

    public void setOriginalFile(byte[] originalFile) {
        this.originalFile = originalFile;
    }

    public byte[] getSignedFile() {
        return signedFile;
    }

    public void setSignedFile(byte[] signedFile) {
        this.signedFile = signedFile;
    }

    public User getUploadedBy() {
        return uploadedBy;
    }

    public void setUploadedBy(User uploadedBy) {
        this.uploadedBy = uploadedBy;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public LocalDateTime getUploadedAt() {
        return uploadedAt;
    }

    public void setUploadedAt(LocalDateTime uploadedAt) {
        this.uploadedAt = uploadedAt;
    }

    public LocalDateTime getSignedAt() {
        return signedAt;
    }

    public void setSignedAt(LocalDateTime signedAt) {
        this.signedAt = signedAt;
    }
}
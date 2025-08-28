package com.pdfsigner.pdf_signer.response;

import java.time.LocalDateTime;

import lombok.Data;

@Data
public class DocumentResponse {
    private Long id;
    private String filename;
    private String status;
    private LocalDateTime uploadedAt;
    private String uploadedBy;

    public DocumentResponse() {
    }

    public DocumentResponse(Long id, String filename, String status,
            LocalDateTime uploadedAt, String uploadedBy) {
        this.id = id;
        this.filename = filename;
        this.status = status;
        this.uploadedAt = uploadedAt;
        this.uploadedBy = uploadedBy;
    }

    // Getters and setters
}

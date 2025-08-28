package com.pdfsigner.pdf_signer.request;

public class DocumentRequest {

    private String filename;
    private byte[] originalFile;

    public DocumentRequest() {
    }

    public DocumentRequest(String filename, byte[] originalFile) {
        this.filename = filename;
        this.originalFile = originalFile;
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
}

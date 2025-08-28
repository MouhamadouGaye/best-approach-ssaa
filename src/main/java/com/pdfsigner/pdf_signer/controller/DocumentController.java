package com.pdfsigner.pdf_signer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.pdfsigner.pdf_signer.model.Document;
import com.pdfsigner.pdf_signer.model.User;
import com.pdfsigner.pdf_signer.repository.UserRepository;
import com.pdfsigner.pdf_signer.request.DocumentRequest;
import com.pdfsigner.pdf_signer.response.DocumentResponse;
import com.pdfsigner.pdf_signer.service.DocumentService;
import com.pdfsigner.pdf_signer.service.UserService;
import com.pdfsigner.pdf_signer.util.PdfSignatureUtil;

import java.security.Principal;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private UserRepository userRepository;
    private DocumentService documentService;
    private UserService userService;
    private PdfSignatureUtil pdfSignatureUtil;

    public DocumentController(
            UserRepository userRepository,
            DocumentService documentService,
            UserService userService,
            PdfSignatureUtil pdfSignatureUtil) {
        this.userRepository = userRepository;
        this.documentService = documentService;
        this.userService = userService;
        this.pdfSignatureUtil = pdfSignatureUtil;

    }

    // @GetMapping
    // public ResponseEntity<List<DocumentResponse>> getAllDocuments(Principal
    // principal) {
    // String email = principal.getName();

    // User user = userRepository.findByEmail(email)
    // .orElseThrow(() -> new UsernameNotFoundException("User not found with email:
    // " + email));

    // List<Document> documents = documentService.getUserDocuments(user);

    // List<DocumentResponse> responses = documents.stream()
    // .map(doc -> new DocumentResponse(
    // doc.getId(),
    // doc.getFilename(),
    // doc.getStatus().name(),
    // doc.getUploadedAt(),
    // doc.getUploadedBy() != null ? doc.getUploadedBy().getEmail() : null))
    // .collect(Collectors.toList());

    // return ResponseEntity.ok(responses);
    // }

    // @PostMapping("/upload")
    // public ResponseEntity<?> uploadDocument(
    // @RequestParam("file") MultipartFile file,
    // @AuthenticationPrincipal UserDetails userDetails) {
    // try {
    // User user = userService.getUserByUsername(userDetails.getUsername());
    // Document document = documentService.uploadDocument(file, user);

    // System.out.println("Received file: " + (file != null ?
    // file.getOriginalFilename() : "null"));

    // return ResponseEntity.ok(document);
    // } catch (Exception e) {
    // return ResponseEntity.badRequest().body(e.getMessage());
    // }
    // }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadDocument(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            System.out.println("File received: " + (file != null ? file.getOriginalFilename() : "null"));
            System.out.println("Authenticated user: " + (userDetails != null ? userDetails.getUsername() : "null"));

            User user = userService.getUserByUsername(userDetails.getUsername());
            Document document = documentService.uploadDocument(file, user);
            return ResponseEntity.ok(document);
        } catch (Exception e) {
            e.printStackTrace(); // for debugging
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping
    public ResponseEntity<?> getUserDocuments(@AuthenticationPrincipal UserDetails userDetails) {
        try {
            User user = userService.getUserByUsername(userDetails.getUsername());
            List<Document> documents = documentService.getUserDocuments(user);
            return ResponseEntity.ok(documents);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getDocument(@PathVariable Long id) {
        try {
            Document document = documentService.getDocument(id);
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"" + document.getFilename() + "\"")
                    .body(document.getOriginalFile());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/{id}/signed")
    public ResponseEntity<?> getSignedDocument(@PathVariable Long id) {
        try {
            Document document = documentService.getDocument(id);
            if (document.getSignedFile() == null) {
                return ResponseEntity.badRequest().body("Document has not been signed yet");
            }
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "inline; filename=\"signed_" + document.getFilename() + "\"")
                    .body(document.getSignedFile());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/{id}/sign")
    public ResponseEntity<?> signDocument(
            @PathVariable Long id,
            @RequestBody Map<String, Object> signatureInfo,
            @AuthenticationPrincipal UserDetails userDetails) {
        try {
            // Extract signature data and position
            String signatureBase64 = (String) signatureInfo.get("signatureData");
            Integer pageNum = (Integer) signatureInfo.get("pageNum");
            Float x = Float.valueOf(signatureInfo.get("x").toString());
            Float y = Float.valueOf(signatureInfo.get("y").toString());
            Float width = Float.valueOf(signatureInfo.get("width").toString());
            Float height = Float.valueOf(signatureInfo.get("height").toString());

            // Remove data:image/png;base64, prefix if present
            String cleanBase64 = signatureBase64;
            if (signatureBase64.contains(",")) {
                cleanBase64 = signatureBase64.split(",")[1];
            }

            byte[] signatureBytes = Base64.getDecoder().decode(cleanBase64);

            // Get the document
            Document document = documentService.getDocument(id);

            // Add signature to PDF
            byte[] signedPdf = pdfSignatureUtil.addSignatureToPdf(
                    document.getOriginalFile(),
                    signatureBytes,
                    pageNum,
                    x, y, width, height);

            // Save the signed document
            Document signedDocument = documentService.signDocument(id, signedPdf);

            return ResponseEntity.ok(signedDocument);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}

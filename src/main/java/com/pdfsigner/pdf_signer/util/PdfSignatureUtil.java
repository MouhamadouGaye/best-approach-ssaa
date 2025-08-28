package com.pdfsigner.pdf_signer.util;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

@Component
public class PdfSignatureUtil {

    public byte[] addSignatureToPdf(byte[] pdfBytes, byte[] signatureImageBytes, int pageNum, float x, float y,
            float width, float height) throws IOException {
        try (PDDocument document = PDDocument.load(new ByteArrayInputStream(pdfBytes))) {
            PDPage page = document.getPage(pageNum);

            // Create image from signature bytes
            PDImageXObject signatureImage = PDImageXObject.createFromByteArray(document, signatureImageBytes,
                    "signature");

            // Add signature to the specified position
            try (PDPageContentStream contentStream = new PDPageContentStream(document, page,
                    PDPageContentStream.AppendMode.APPEND, true, true)) {
                contentStream.drawImage(signatureImage, x, y, width, height);
            }

            // Save the document to byte array
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            return baos.toByteArray();
        }
    }
}
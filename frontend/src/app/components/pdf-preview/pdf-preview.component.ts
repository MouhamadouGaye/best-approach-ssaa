// // pdf-preview.component.ts
// import { Component, Input, NgModule, OnInit } from '@angular/core';
// // import { SignatureService } from '../services/signature.service';
// import { DocumentService } from '../../services/document.service';
// import { SignaturePosition } from '../../models/signature-position.model';
// import { SignatureService } from '../../services/signature.service';
// import { ViewChild } from '@angular/core';
// import { PdfViewerComponent } from 'ng2-pdf-viewer';
// import { CommonModule } from '@angular/common';

// @Component({
//   selector: 'app-pdf-preview',
//   templateUrl: './pdf-preview.component.html',
//   styleUrls: ['./pdf-preview.component.scss'],
//   imports: [CommonModule],
// })
// export class PdfPreviewComponent implements OnInit {
//   @ViewChild(PdfViewerComponent) private pdfViewer!: PdfViewerComponent;
//   @Input() documentId!: number;
//   pdfSrc: string | null = null;
//   signatureData: string | null = null;

//   totalPages = 1;

//   constructor(
//     private signatureService: SignatureService,
//     private documentService: DocumentService
//   ) {}

//   ngOnInit(): void {
//     this.loadPdf();
//     this.signatureService.getSignature().subscribe((sig) => {
//       this.signatureData = sig?.dataUrl || null;
//     });
//   }

//   async loadPdf() {
//     this.documentService
//       .getDocument(this.documentId)
//       .subscribe((arrayBuffer) => {
//         const blob = new Blob([arrayBuffer], { type: 'application/pdf' });
//         this.pdfSrc = URL.createObjectURL(blob);
//       });
//   }

//   onPlaceSignature() {
//     if (!this.signatureData) {
//       alert('No signature found. Please create a signature first.');
//       return;
//     }

//     const position: SignaturePosition = {
//       pageNum: 1, // You might want to calculate the last page dynamically
//       x: 100, // Example coordinates
//       y: 100,
//       width: 150,
//       height: 50,
//     };

//     this.documentService
//       .signDocument(this.documentId, this.signatureData, position)
//       .subscribe(() => {
//         alert('Document signed successfully!');
//         this.loadPdf(); // Refresh the preview
//       });
//   }

//   onPdfLoadComplete(pdf: any): void {
//     this.totalPages = pdf.numPages;
//   }
// }

import {
  Component,
  CUSTOM_ELEMENTS_SCHEMA,
  Input,
  OnInit,
  ViewChild,
} from '@angular/core';
import { DocumentService } from '../../services/document.service';
import { SignaturePosition } from '../../models/signature-position.model';
import { SignatureService } from '../../services/signature.service';
import { PdfViewerComponent } from 'ng2-pdf-viewer';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-pdf-preview',
  templateUrl: './pdf-preview.component.html',
  styleUrls: ['./pdf-preview.component.scss'],
  imports: [CommonModule],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
})
export class PdfPreviewComponent implements OnInit {
  @ViewChild(PdfViewerComponent) private pdfViewer!: PdfViewerComponent;
  @Input() documentId!: number;
  pdfSrc: string | null = null;
  signatureData: string | null = null;

  totalPages = 1;
  currentPage = 1; // To track the current page

  constructor(
    private signatureService: SignatureService,
    private documentService: DocumentService
  ) {}

  ngOnInit(): void {
    this.loadPdf();
    this.signatureService.getSignatures(1, 10, '').subscribe((sig) => {
      this.signatureData = sig && sig.dataUrl ? sig.dataUrl : null;
    });
  }

  // Load the PDF document from the service
  async loadPdf() {
    this.documentService
      .getDocument(this.documentId)
      .subscribe((arrayBuffer) => {
        const blob = new Blob([arrayBuffer], { type: 'application/pdf' });
        this.pdfSrc = URL.createObjectURL(blob);
      });
  }

  // Event handler when the PDF is fully loaded
  onPdfLoadComplete(pdf: any): void {
    this.totalPages = pdf.numPages;
  }

  // Place the signature on the PDF document
  onPlaceSignature() {
    if (!this.signatureData) {
      alert('No signature found. Please create a signature first.');
      return;
    }

    // Prompt the user to select where to place the signature
    const x = prompt('Enter X position for the signature (px)', '100');
    const y = prompt('Enter Y position for the signature (px)', '100');

    if (x && y) {
      const position: SignaturePosition = {
        pageNum: this.currentPage, // Use the current page to place the signature
        x: parseInt(x, 10),
        y: parseInt(y, 10),
        width: 150, // Fixed width of the signature
        height: 50, // Fixed height of the signature
      };

      // Call the service to save the signature on the document
      this.documentService
        .signDocument(this.documentId, this.signatureData, [position])
        .subscribe(() => {
          alert('Document signed successfully!');
          this.loadPdf(); // Refresh the PDF after signing
        });
    } else {
      alert('Invalid position entered.');
    }
  }

  // Go to the next page in the document
  onNextPage() {
    if (this.currentPage < this.totalPages) {
      this.currentPage++;
      this.pdfViewer.page = this.currentPage; // Refresh the current page
    }
  }

  // Go to the previous page in the document
  onPreviousPage() {
    if (this.currentPage > 1) {
      this.currentPage--;
      this.pdfViewer.page = this.currentPage; // Refresh the current page
    }
  }

  // Update the current page when the user clicks on the PDF viewer
  onPageChange(page: number) {
    this.currentPage = page;
  }

  onSignatureCaptured(signature: Event) {
    this.signatureData = signature.toString();
  }
}

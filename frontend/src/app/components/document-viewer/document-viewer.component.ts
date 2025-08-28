// // File: app/components/document-viewer/document-viewer.component.ts
// import {
//   Component,
//   OnInit,
//   ViewChild,
//   ElementRef,
//   NgZone,
//   NgModule,
//   Input,
// } from '@angular/core';
// import { ActivatedRoute, Router } from '@angular/router';
// import { Document } from '../../models/document.model';
// import { SignaturePosition } from '../../models/signature-position.model';
// import { DocumentService } from '../../services/document.service';
// import { AuthService } from '../../services/auth.service';
// import * as pdfjsLib from 'pdfjs-dist';
// import { Subject } from 'rxjs';
// import { takeUntil } from 'rxjs/operators';
// import { SignaturePadComponent } from '../signature-pad/signature-pad.component';
// import { FormsModule } from '@angular/forms';
// import { CommonModule } from '@angular/common';

// // Ensure PDF.js worker is available
// pdfjsLib.GlobalWorkerOptions.workerSrc = 'assets/pdf.worker.min.js';

// @Component({
//   selector: 'app-document-viewer',
//   templateUrl: './document-viewer.component.html',
//   styleUrls: ['./document-viewer.component.scss'],
//   imports: [SignaturePadComponent, FormsModule, CommonModule],
// })
// export class DocumentViewerComponent implements OnInit {
//   @Input() signatureData: string = '';
//   @ViewChild('pdfContainer') pdfContainer!: ElementRef;
//   @ViewChild('signatureCanvas') signatureCanvas!: ElementRef<HTMLCanvasElement>;

//   documentId!: number;
//   document: Document | null = null;
//   loading = true;
//   error: string | null = null;

//   // PDF rendering
//   pdf: any = null;
//   currentPage = 1;
//   totalPages = 0;
//   zoom = 1.0;
//   rotation = 0;

//   // Signature positioning
//   isPlacingSignature = false;
//   signaturePositions: SignaturePosition[] = [];
//   selectedSignaturePosition: SignaturePosition | null = null;
//   signatureDataUrl: string | null = null;

//   private readonly SCALE = window.devicePixelRatio || 1;
//   private unsubscribe$ = new Subject<void>();

//   constructor(
//     private route: ActivatedRoute,
//     private router: Router,
//     private documentService: DocumentService,
//     private authService: AuthService,
//     private ngZone: NgZone
//   ) {}

//   ngOnInit(): void {
//     this.route.params.pipe(takeUntil(this.unsubscribe$)).subscribe((params) => {
//       this.documentId = +params['id'];
//       this.loadDocument();
//     });
//   }

//   ngOnDestroy(): void {
//     this.unsubscribe$.next();
//     this.unsubscribe$.complete();
//   }

//   loadDocument(): void {
//     this.loading = true;
//     this.error = null;

//     this.documentService.getDocumentById(this.documentId).subscribe({
//       next: (document) => {
//         this.document = document;
//         this.loadPdf();
//       },
//       error: (err) => {
//         console.error('Error loading document', err);
//         this.error = 'Failed to load document. Please try again later.';
//         this.loading = false;
//       },
//     });
//   }

//   loadPdf(): void {
//     // In a real app, you would load from the document's URL or get the blob from the server
//     const pdfUrl = `${this.documentService.apiUrl}/${this.documentId}/download`;
//     const token = this.authService.getToken();

//     // Load the PDF
//     pdfjsLib
//       .getDocument({
//         url: pdfUrl,
//         httpHeaders: { Authorization: `Bearer ${token}` },
//       })
//       .promise.then((pdf: any) => {
//         this.ngZone.run(() => {
//           this.pdf = pdf;
//           this.totalPages = pdf.numPages;
//           this.loading = false;

//           // Render the first page
//           this.renderPage(this.currentPage);
//         });
//       })
//       .catch((err: any) => {
//         this.ngZone.run(() => {
//           console.error('Error loading PDF', err);
//           this.error = 'Failed to load document. Please try again later.';
//           this.loading = false;
//         });
//       });
//   }

//   renderPage(pageNumber: number): void {
//     if (!this.pdf) return;

//     this.loading = true;

//     // Get the page
//     this.pdf.getPage(pageNumber).then((page: any) => {
//       const container = this.pdfContainer.nativeElement;
//       const canvas = document.createElement('canvas');

//       // Clear existing content
//       container.innerHTML = '';
//       container.appendChild(canvas);

//       const viewport = page.getViewport({
//         scale: this.zoom,
//         rotation: this.rotation,
//       });

//       // Set canvas dimensions
//       canvas.width = viewport.width * this.SCALE;
//       canvas.height = viewport.height * this.SCALE;
//       canvas.style.width = `${viewport.width}px`;
//       canvas.style.height = `${viewport.height}px`;

//       const context = canvas.getContext('2d');
//       if (!context) return;

//       context.scale(this.SCALE, this.SCALE);

//       // Render the page
//       const renderContext = {
//         canvasContext: context,
//         viewport: viewport,
//       };

//       page
//         .render(renderContext)
//         .promise.then(() => {
//           this.ngZone.run(() => {
//             this.loading = false;

//             // Render signature positions if any
//             this.renderSignaturePositions();
//           });
//         })
//         .catch((err: any) => {
//           this.ngZone.run(() => {
//             console.error('Error rendering page', err);
//             this.error = 'Failed to render page. Please try again later.';
//             this.loading = false;
//           });
//         });
//     });
//   }

//   renderSignaturePositions(): void {
//     const container = this.pdfContainer.nativeElement;

//     // Clear existing signatures
//     const existingSignatures = container.querySelectorAll('.signature-overlay');
//     existingSignatures.forEach((el: Element) => el.remove());

//     // Add signature overlays
//     this.signaturePositions.forEach((position, index) => {
//       if (position.pageNum === this.currentPage) {
//         const overlay = document.createElement('div');
//         overlay.className = 'signature-overlay';
//         overlay.style.left = `${position.x}px`;
//         overlay.style.top = `${position.y}px`;
//         overlay.style.width = `${position.width}px`;
//         overlay.style.height = `${position.height}px`;

//         if (this.signatureDataUrl) {
//           const img = document.createElement('img');
//           img.src = this.signatureDataUrl;
//           img.style.width = '100%';
//           img.style.height = '100%';
//           overlay.appendChild(img);
//         }

//         overlay.addEventListener('click', () => {
//           this.selectedSignaturePosition = position;
//         });

//         container.appendChild(overlay);
//       }
//     });
//   }

//   prevPage(): void {
//     if (this.currentPage > 1) {
//       this.currentPage--;
//       this.renderPage(this.currentPage);
//     }
//   }

//   nextPage(): void {
//     if (this.currentPage < this.totalPages) {
//       this.currentPage++;
//       this.renderPage(this.currentPage);
//     }
//   }

//   zoomIn(): void {
//     this.zoom *= 1.2;
//     this.renderPage(this.currentPage);
//   }

//   zoomOut(): void {
//     this.zoom /= 1.2;
//     this.renderPage(this.currentPage);
//   }

//   rotateClockwise(): void {
//     this.rotation = (this.rotation + 90) % 360;
//     this.renderPage(this.currentPage);
//   }

//   startSignaturePlacement(): void {
//     this.isPlacingSignature = true;
//     this.pdfContainer.nativeElement.style.cursor = 'crosshair';
//   }

//   cancelSignaturePlacement(): void {
//     this.isPlacingSignature = false;
//     this.pdfContainer.nativeElement.style.cursor = 'default';
//   }

//   handleContainerClick(event: MouseEvent): void {
//     if (!this.isPlacingSignature || !this.signatureDataUrl) return;

//     const container = this.pdfContainer.nativeElement;
//     const rect = container.getBoundingClientRect();

//     // Calculate position relative to the container
//     const x = event.clientX - rect.left;
//     const y = event.clientY - rect.top;

//     // Default signature size (you might want to make this customizable)
//     const width = 200;
//     const height = 100;

//     // Add new signature position
//     const newPosition: SignaturePosition = {
//       pageNum: this.currentPage,
//       x,
//       y,
//       width,
//       height,
//     };

//     this.signaturePositions.push(newPosition);
//     this.selectedSignaturePosition = newPosition;

//     // Render the updated signature positions
//     this.renderSignaturePositions();

//     // Exit placement mode
//     this.isPlacingSignature = false;
//     this.pdfContainer.nativeElement.style.cursor = 'default';
//   }

//   removeSignature(index: number): void {
//     this.signaturePositions.splice(index, 1);
//     this.selectedSignaturePosition = null;
//     this.renderSignaturePositions();
//   }

//   saveSignatures(): void {
//     if (
//       !this.document ||
//       !this.signatureDataUrl ||
//       this.signaturePositions.length === 0
//     ) {
//       return;
//     }

//     this.loading = true;

//     this.documentService
//       .signDocument(
//         this.document.id!,
//         this.signatureDataUrl,
//         this.signaturePositions
//       )
//       .subscribe({
//         next: (document) => {
//           this.document = document;
//           this.loading = false;
//           // Navigate back to document list
//           this.router.navigate(['/documents']);
//         },
//         error: (err) => {
//           console.error('Error signing document', err);
//           this.error = 'Failed to sign document. Please try again later.';
//           this.loading = false;
//         },
//       });
//   }

//   onSignatureCreated(signatureData: string): void {
//     this.signatureDataUrl = signatureData;
//   }

//   downloadDocument(): void {
//     if (!this.document) return;

//     this.documentService.downloadDocument(this.document.id!).subscribe({
//       next: (blob) => {
//         const url = window.URL.createObjectURL(blob);
//         const link = document.createElement('a');
//         link.href = url;
//         link.download = this.document?.filename || 'document.pdf';
//         link.click();
//         window.URL.revokeObjectURL(url);
//       },
//       error: (err) => {
//         console.error('Error downloading document', err);
//         this.error = 'Failed to download document. Please try again later.';
//       },
//     });
//   }

//   goBack(): void {
//     this.router.navigate(['/documents']);
//   }
// }

// // document-viewer.component.ts
// import {
//   Component,
//   OnInit,
//   Inject,
//   CUSTOM_ELEMENTS_SCHEMA,
//   Output,
//   EventEmitter,
// } from '@angular/core';
// import { ActivatedRoute } from '@angular/router';
// import { MatSnackBar } from '@angular/material/snack-bar';
// import { DocumentService } from '../../services/document.service';
// import { SignatureService } from '../../services/signature.service';
// import { MatLabel } from '@angular/material/form-field';
// import {
//   MatCard,
//   MatCardContent,
//   MatCardHeader,
//   MatCardTitle,
// } from '@angular/material/card';
// import { MatIcon } from '@angular/material/icon';
// import { MatTab, MatTabGroup } from '@angular/material/tabs';
// import { MatSpinner } from '@angular/material/progress-spinner';
// import { CommonModule } from '@angular/common';

// interface Signature {
//   id: string;
//   dataUrl: string;
//   name: string;
//   created: Date;
// }

// @Component({
//   selector: 'app-document-viewer',
//   imports: [
//     MatCardContent,
//     MatIcon,
//     MatCard,
//     MatCardContent,
//     MatTabGroup,
//     MatTab,
//     MatSpinner,
//     MatCardHeader,
//     MatCardTitle,
//     CommonModule,
//   ],
//   template: `
//     <div class="document-viewer-container">
//       <div class="header-row">
//         <h2>{{ document?.name || 'Document Viewer' }}</h2>

//         <div class="action-buttons">
//           <button mat-raised-button color="accent" (click)="toggleSignMode()">
//             <mat-icon>{{ signingMode ? 'cancel' : 'draw' }}</mat-icon>
//             {{ signingMode ? 'Cancel Signing' : 'Sign Document' }}
//           </button>

//           <button
//             mat-raised-button
//             color="primary"
//             *ngIf="signingMode"
//             (click)="saveSignedDocument()"
//           >
//             <mat-icon>save</mat-icon>
//             Save Signed Document
//           </button>

//           <button mat-raised-button (click)="downloadDocument()">
//             <mat-icon>download</mat-icon>
//             Download
//           </button>
//         </div>
//       </div>

//       <div class="content-container">
//         <div class="document-panel">
//           <div class="loading-container" *ngIf="isLoading">
//             <mat-spinner diameter="40"></mat-spinner>
//           </div>

//           <div #pdfContainer class="pdf-container" *ngIf="!isLoading">
//             <!-- PDF will be rendered here -->
//           </div>
//         </div>

//         <mat-card class="signature-panel" *ngIf="signingMode">
//           <mat-card-header>
//             <mat-card-title>Signature Tools</mat-card-title>
//           </mat-card-header>

//           <mat-card-content>
//             <mat-tab-group>
//               <mat-tab label="My Signatures">
//                 <div class="signature-list-container">
//                   <div class="loading-container" *ngIf="signaturesLoading">
//                     <mat-spinner diameter="30"></mat-spinner>
//                   </div>

//                   <div
//                     *ngIf="!signaturesLoading && signatures.length === 0"
//                     class="no-signatures"
//                   >
//                     <p>You don't have any saved signatures.</p>
//                     <button mat-button color="primary" (click)="switchTab(1)">
//                       Create New Signature
//                     </button>
//                   </div>

//                   <div
//                     *ngIf="!signaturesLoading && signatures.length > 0"
//                     class="signatures-grid"
//                   >
//                     <div
//                       *ngFor="let signature of signatures"
//                       class="signature-item"
//                     >
//                       <img
//                         [src]="signature.dataUrl"
//                         alt="Signature"
//                         (click)="applySignature(signature)"
//                       />
//                       <div class="signature-name">{{ signature.name }}</div>
//                     </div>
//                   </div>
//                 </div>
//               </mat-tab>

//               <mat-tab label="Create Signature">
//                 <app-signature-pad
//                   (signatureCreated)="onSignatureCreated($event)"
//                 ></app-signature-pad>
//               </mat-tab>
//             </mat-tab-group>
//           </mat-card-content>
//         </mat-card>
//       </div>
//     </div>
//   `,
//   styles: [
//     `
//       .document-viewer-container {
//         padding: 20px;
//       }
//       .header-row {
//         display: flex;
//         justify-content: space-between;
//         align-items: center;
//         margin-bottom: 20px;
//       }
//       .action-buttons button {
//         margin-left: 10px;
//       }
//       .content-container {
//         display: flex;
//         gap: 20px;
//       }
//       .document-panel {
//         flex: 2;
//         position: relative;
//         min-height: 500px;
//         border: 1px solid #ddd;
//         border-radius: 4px;
//         background-color: #f5f5f5;
//       }
//       .signature-panel {
//         flex: 1;
//         max-width: 350px;
//       }
//       .loading-container {
//         display: flex;
//         justify-content: center;
//         padding: 20px;
//       }
//       .pdf-container {
//         width: 100%;
//         height: 100%;
//         min-height: 500px;
//       }
//       .no-signatures {
//         padding: 20px;
//         text-align: center;
//       }
//       .signatures-grid {
//         display: grid;
//         grid-template-columns: repeat(2, 1fr);
//         gap: 15px;
//         padding: 15px;
//       }
//       .signature-item {
//         border: 1px solid #ddd;
//         border-radius: 4px;
//         padding: 10px;
//         cursor: pointer;
//         transition: all 0.2s;
//       }
//       .signature-item:hover {
//         border-color: #007bff;
//         transform: scale(1.02);
//       }
//       .signature-item img {
//         width: 100%;
//         height: 80px;
//         object-fit: contain;
//       }
//       .signature-name {
//         margin-top: 8px;
//         font-size: 12px;
//         text-align: center;
//         white-space: nowrap;
//         overflow: hidden;
//         text-overflow: ellipsis;
//       }
//     `,
//   ],

//   schemas: [CUSTOM_ELEMENTS_SCHEMA],
// })
// export class DocumentViewerComponent implements OnInit {
//   document: any;
//   isLoading = true;
//   signingMode = false;
//   signatures: Signature[] = [];
//   signaturesLoading = false;

//   constructor(
//     private route: ActivatedRoute,
//     private documentService: DocumentService,
//     @Inject(SignatureService) private signatureService: SignatureService,
//     private snackBar: MatSnackBar
//   ) {}

//   ngOnInit(): void {
//     const documentId = this.route.snapshot.paramMap.get('id');
//     if (documentId) {
//       this.loadDocument(documentId);
//     }
//   }

//   loadDocument(id: string): void {
//     this.isLoading = true;
//     this.documentService.getDocument(id).subscribe({
//       next: (document) => {
//         this.document = document;
//         this.isLoading = false;
//         // Here you would render the PDF using a library like PDF.js
//       },
//       error: (error) => {
//         this.isLoading = false;
//         this.snackBar.open('Failed to load document', 'Close', {
//           duration: 5000,
//           panelClass: ['error-snackbar'],
//         });
//       },
//     });
//   }

//   toggleSignMode(): void {
//     this.signingMode = !this.signingMode;
//     if (this.signingMode) {
//       this.loadSignatures();
//     }
//   }

//   loadSignatures(): void {
//     this.signaturesLoading = true;
//     this.signatureService.getSignature().subscribe({
//       next: (signatures) => {
//         this.signatures = signatures;
//         this.signaturesLoading = false;
//       },
//       error: (error) => {
//         this.signaturesLoading = false;
//         this.snackBar.open('Failed to load signatures', 'Close', {
//           duration: 5000,
//           panelClass: ['error-snackbar'],
//         });
//       },
//     });
//   }

//   switchTab(index: number): void {
//     // In a real application, you would need to access the MatTabGroup
//     // via ViewChild and programmatically select the tab
//   }

//   applySignature(signature: Signature): void {
//     // Logic to apply the signature to the document
//     this.snackBar.open(
//       'Signature added to document. Click and drag to position it.',
//       'Close',
//       {
//         duration: 3000,
//       }
//     );
//   }

//   onSignatureCreated(signatureData: string): void {
//     // Here you would save the new signature and add it to the document
//     const name = prompt('Enter a name for this signature:');
//     if (name) {
//       this.signatureService.saveSignature(name, signatureData).subscribe({
//         next: (savedSignature) => {
//           this.signatures.push(savedSignature);
//           this.applySignature(savedSignature);
//           this.snackBar.open(
//             'Signature saved and applied to document',
//             'Close',
//             {
//               duration: 3000,
//               panelClass: ['success-snackbar'],
//             }
//           );
//           this.switchTab(0);
//         },
//         error: (error) => {
//           this.snackBar.open('Failed to save signature', 'Close', {
//             duration: 5000,
//             panelClass: ['error-snackbar'],
//           });
//         },
//       });
//     }
//   }

//   saveSignedDocument(): void {
//     // Logic to save the document with signatures
//     this.snackBar.open('Document signed and saved successfully', 'Close', {
//       duration: 3000,
//       panelClass: ['success-snackbar'],
//     });
//     this.signingMode = false;
//   }

//   downloadDocument(): void {
//     // Logic to download the document
//     this.documentService.downloadDocument(this.document.id).subscribe({
//       next: (blob) => {
//         const url = window.URL.createObjectURL(blob);
//         const a = document.createElement('a');
//         a.href = url;
//         a.download = this.document.name;
//         document.body.appendChild(a);
//         a.click();
//         window.URL.revokeObjectURL(url);
//         a.remove();
//       },
//       error: (error) => {
//         this.snackBar.open('Failed to download document', 'Close', {
//           duration: 5000,
//           panelClass: ['error-snackbar'],
//         });
//       },
//     });
//   }
// }

import {
  Component,
  OnInit,
  Inject,
  CUSTOM_ELEMENTS_SCHEMA,
  ViewChild,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';
import { DocumentService } from '../../services/document.service';
import { SignatureService } from '../../services/signature.service';
import { MatTabGroup } from '@angular/material/tabs';
import { CommonModule } from '@angular/common';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatTabsModule } from '@angular/material/tabs';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { PdfViewerComponent } from 'ng2-pdf-viewer';

interface Signature {
  id: string;
  dataUrl: string;
  name: string;
  created: Date;
}

@Component({
  selector: 'app-document-viewer',
  standalone: true,
  imports: [
    CommonModule,
    MatButtonModule,
    MatIconModule,
    MatCardModule,
    MatTabsModule,
    MatProgressSpinnerModule,
  ],
  template: `
    <div class="document-viewer-container">
      <div class="header-row">
        <h2>{{ document?.name || 'Document Viewer' }}</h2>

        <div class="action-buttons">
          <button mat-raised-button color="accent" (click)="toggleSignMode()">
            <mat-icon>{{ signingMode ? 'cancel' : 'draw' }}</mat-icon>
            {{ signingMode ? 'Cancel Signing' : 'Sign Document' }}
          </button>

          <button
            mat-raised-button
            color="primary"
            *ngIf="signingMode"
            (click)="saveSignedDocument()"
          >
            <mat-icon>save</mat-icon>
            Save Signed Document
          </button>

          <button mat-raised-button (click)="downloadDocument()">
            <mat-icon>download</mat-icon>
            Download
          </button>
        </div>
      </div>

      <div class="content-container">
        <div class="document-panel">
          <div class="loading-container" *ngIf="isLoading">
            <mat-spinner diameter="40"></mat-spinner>
          </div>

          <div #pdfContainer class="pdf-container" *ngIf="!isLoading">
            <!-- PDF will be rendered here -->
            <pdf-viewer
              #pdfViewer
              [src]="pdfSrc"
              [render-text]="true"
              (after-load-complete)="onPdfLoadComplete($event)"
              style="width: 100%; height: 90vh;"
            ></pdf-viewer>
          </div>
        </div>

        <mat-card class="signature-panel" *ngIf="signingMode">
          <mat-card-header>
            <mat-card-title>Signature Tools</mat-card-title>
          </mat-card-header>

          <mat-card-content>
            <mat-tab-group #tabGroup>
              <app-signature-canvas
                (signatureSaved)="onSignatureCaptured($event)"
              ></app-signature-canvas>

              <mat-tab label="My Signatures">
                <div class="signature-list-container">
                  <div class="loading-container" *ngIf="signaturesLoading">
                    <mat-spinner diameter="30"></mat-spinner>
                  </div>

                  <div
                    *ngIf="!signaturesLoading && signatures.length === 0"
                    class="no-signatures"
                  >
                    <p>You don't have any saved signatures.</p>
                    <button mat-button color="primary" (click)="switchTab(1)">
                      Create New Signature
                    </button>
                  </div>

                  <div
                    *ngIf="!signaturesLoading && signatures.length > 0"
                    class="signatures-grid"
                  >
                    <div
                      *ngFor="let signature of signatures"
                      class="signature-item"
                    >
                      <img
                        [src]="signature.dataUrl"
                        alt="Signature"
                        (click)="applySignature(signature)"
                      />
                      <div class="signature-name">{{ signature.name }}</div>
                    </div>
                  </div>
                </div>
              </mat-tab>

              <mat-tab label="Create Signature">
                <app-signature-pad
                  (signatureCreated)="onSignatureCreated($event)"
                ></app-signature-pad>
              </mat-tab>
            </mat-tab-group>
          </mat-card-content>
        </mat-card>
      </div>
    </div>
  `,
  styles: [
    `
      .document-viewer-container {
        padding: 20px;
      }
      .header-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
      }
      .action-buttons button {
        margin-left: 10px;
      }
      .content-container {
        display: flex;
        gap: 20px;
      }
      .document-panel {
        flex: 2;
        position: relative;
        min-height: 500px;
        border: 1px solid #ddd;
        border-radius: 4px;
        background-color: #f5f5f5;
      }
      .signature-panel {
        flex: 1;
        max-width: 350px;
      }
      .loading-container {
        display: flex;
        justify-content: center;
        padding: 20px;
      }
      .pdf-container {
        width: 100%;
        height: 100%;
        min-height: 500px;
      }
      .no-signatures {
        padding: 20px;
        text-align: center;
      }
      .signatures-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 15px;
        padding: 15px;
      }
      .signature-item {
        border: 1px solid #ddd;
        border-radius: 4px;
        padding: 10px;
        cursor: pointer;
        transition: all 0.2s;
      }
      .signature-item:hover {
        border-color: #007bff;
        transform: scale(1.02);
      }
      .signature-item img {
        width: 100%;
        height: 80px;
        object-fit: contain;
      }
      .signature-name {
        margin-top: 8px;
        font-size: 12px;
        text-align: center;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
    `,
  ],
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
})
export class DocumentViewerComponent implements OnInit {
  document: any;
  isLoading = true;
  signingMode = false;
  signatures: Signature[] = [];
  signaturesLoading = false;
  documentId: number = 0;

  pdfSrc: string | null = null;
  loading = true; // Loading flag to show spinner

  totalPages: number = 1;
  signatureData: string | null = null;
  currentDrawnSignature: string | null = null;
  error: string | null = null; // Error message

  @ViewChild('tabGroup') tabGroup!: MatTabGroup;
  @ViewChild('pdfViewer') pdfViewer!: PdfViewerComponent;

  constructor(
    private route: ActivatedRoute,
    private documentService: DocumentService,
    @Inject(SignatureService) private signatureService: SignatureService,
    private snackBar: MatSnackBar
  ) {}

  // ngOnInit(): void {
  //   const documentId = this.route.snapshot.paramMap.get('id');
  //   if (documentId) {
  //     this.loadDocument(documentId);
  //   }
  // }

  // ngOnInit() {
  //   this.documentId = +this.route.snapshot.paramMap.get('id')!; // Get the document ID from the route

  //   const file = this.documentService.getFile();
  //   if (file) {
  //     this.pdfSrc = URL.createObjectURL(file); // for pdf-viewer
  //   } else {
  //     // Redirect or show error
  //   }
  // }

  // ngOnInit() {
  //   this.route.params.subscribe((params) => {
  //     this.documentId = +params['id']; // Get the document ID from the URL
  //     this.loadDocument();
  //   });
  // }

  ngOnInit() {
    this.route.params.subscribe((params) => {
      this.documentId = +params['id'];
      this.loadDocument();
    });

    this.route.queryParams.subscribe((q) => {
      if (q['sign']) {
        this.signingMode = true;
        this.loadSignatures();
      }
    });
  }

  onSignatureCaptured(event: Event) {
    const signatureDataUrl = (event as any).detail || '';
    // Save the drawn signature temporarily
    this.currentDrawnSignature = signatureDataUrl;
    console.log('Signature captured from canvas:', signatureDataUrl);

    // If needed, apply it immediately:
    this.applySignature({
      id: 'drawn-signature',
      dataUrl: signatureDataUrl,
      name: 'Drawn Signature',
      created: new Date(),
    });
  }

  // loadDocument(id: string): void {
  //   this.isLoading = true;
  //   const documentId = Number(this.route.snapshot.paramMap.get('id'));

  //   // this.documentService.getDocument(id).subscribe({
  //   this.documentService.getDocument(documentId).subscribe({
  //     next: (document) => {
  //       this.document = document;
  //       this.isLoading = false;
  //       // Here you would render the PDF using a library like PDF.js
  //       // Load PDF blob as URL
  //       // const blob = new Blob([document.blob], { type: 'application/pdf' }); // With this I get this error: ✘ [ERROR] TS2339: Property 'blob' does not exist on type 'ArrayBuffer'. [plugin angular-compiler]
  //       const blob = new Blob([document], { type: 'application/pdf' });

  //       this.pdfSrc = URL.createObjectURL(blob);
  //     },
  //     error: (error: any) => {
  //       this.isLoading = false;
  //       this.snackBar.open('Failed to load document', 'Close', {
  //         duration: 5000,
  //         panelClass: ['error-snackbar'],
  //       });
  //     },
  //   });
  // }

  loadDocument() {
    this.documentService.getDocument(this.documentId).subscribe(
      (arrayBuffer: ArrayBuffer) => {
        const blob = new Blob([arrayBuffer], { type: 'application/pdf' });
        this.pdfSrc = URL.createObjectURL(blob);
        this.loading = false;
      },
      (error) => {
        this.error = 'Failed to load document';
        this.loading = false;
      }
    );
  }

  toggleSignMode(): void {
    this.signingMode = !this.signingMode;
    if (this.signingMode) {
      this.loadSignatures();
    }
  }

  loadSignatures(): void {
    this.signaturesLoading = true;
    this.signatureService.getSignatures().subscribe({
      next: (signatures: any) => {
        this.signatures = signatures;
        this.signaturesLoading = false;
      },
      error: (error: any) => {
        this.signaturesLoading = false;
        this.snackBar.open('Failed to load signatures', 'Close', {
          duration: 5000,
          panelClass: ['error-snackbar'],
        });
      },
    });
  }

  switchTab(index: number): void {
    if (this.tabGroup) {
      this.tabGroup.selectedIndex = index;
    }
  }

  applySignature(signature: Signature): void {
    // Logic to apply the signature to the document
    this.snackBar.open(
      'Signature added to document. Click and drag to position it.',
      'Close',
      {
        duration: 3000,
      }
    );
  }

  // applySignature(signature: Signature): void {
  //   if (!this.totalPages) {
  //     this.snackBar.open('PDF not fully loaded yet.', 'Close', {
  //       duration: 3000,
  //     });
  //     return;
  //   }

  //   const position = {
  //     pageNum: this.totalPages,
  //     x: 100,
  //     y: 100, // You can refine this using actual PDF height if needed
  //     width: 150,
  //     height: 50,
  //   };

  //   this.documentService
  //     .signDocument(this.document.id, signature.dataUrl, position)
  //     .subscribe(() => {
  //       this.snackBar.open('Signature placed and saved.', 'Close', {
  //         duration: 3000,
  //         panelClass: ['success-snackbar'],
  //       });
  //       this.loadDocument(); // Refresh preview
  //     });
  // }

  onSignatureCreated(signatureData: any): void {
    // Here you would save the new signature and add it to the document
    const name = prompt('Enter a name for this signature:');
    if (name) {
      this.signatureService.saveSignature(name, signatureData).subscribe({
        next: (savedSignature: any) => {
          this.signatures.push(savedSignature);
          this.applySignature(savedSignature);
          this.snackBar.open(
            'Signature saved and applied to document',
            'Close',
            {
              duration: 3000,
              panelClass: ['success-snackbar'],
            }
          );
          this.switchTab(0);
        },
        error: (error: any) => {
          this.snackBar.open('Failed to save signature', 'Close', {
            duration: 5000,
            panelClass: ['error-snackbar'],
          });
        },
      });
    }
  }

  saveSignedDocument(): void {
    // Logic to save the document with signatures
    this.snackBar.open('Document signed and saved successfully', 'Close', {
      duration: 3000,
      panelClass: ['success-snackbar'],
    });
    this.signingMode = false;
  }

  downloadDocument(): void {
    // Logic to download the document
    if (!this.document || !this.document.id) {
      this.snackBar.open('Document ID is missing', 'Close', {
        duration: 5000,
        panelClass: ['error-snackbar'],
      });
      return;
    }

    this.documentService.downloadDocument(this.document.id).subscribe({
      next: (blob: Blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = this.document.name || 'document';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
      },
      error: (error: any) => {
        this.snackBar.open('Failed to download document', 'Close', {
          duration: 5000,
          panelClass: ['error-snackbar'],
        });
      },
    });
  }

  onPdfLoadComplete(pdf: any): void {
    this.totalPages = pdf.numPages;
  }

  uploadedFile: File | null = null;

  onFileUploaded(file: File) {
    this.uploadedFile = file;
  }
}

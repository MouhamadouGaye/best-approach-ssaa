// // File: app/components/document-upload/document-upload.component.ts
// import { Component, OnInit, ViewChild, ElementRef } from '@angular/core';
// import { FormBuilder, FormGroup, Validators } from '@angular/forms';
// import { Router } from '@angular/router';
// import { DocumentService } from '../../services/document.service';
// import { MatSnackBar } from '@angular/material/snack-bar';
// import { HttpEventType, HttpResponse } from '@angular/common/http';
// import { MatIcon } from '@angular/material/icon';
// import {
//   MatCard,
//   MatCardActions,
//   MatCardContent,
//   MatCardHeader,
//   MatCardTitle,
// } from '@angular/material/card';
// import {
//   MatError,
//   MatFormField,
//   MatFormFieldControl,
//   MatFormFieldModule,
// } from '@angular/material/form-field';
// import { MatDialog } from '@angular/material/dialog';
// import { MatDatepickerModule } from '@angular/material/datepicker';
// import { MatNativeDateModule } from '@angular/material/core';
// import { CommonModule } from '@angular/common';
// import { MatProgressBarModule } from '@angular/material/progress-bar';
// import { BrowserModule } from '@angular/platform-browser';
// import { FormsModule, ReactiveFormsModule } from '@angular/forms';

// @Component({
//   selector: 'app-document-upload',
//   templateUrl: './document-upload.component.html',
//   styleUrls: ['./document-upload.component.scss'],
//   imports: [
//     MatIcon,
//     MatCardContent,
//     MatCard,
//     MatError,
//     MatCardHeader,
//     MatCardTitle,
//     MatFormField,
//     MatFormFieldModule,
//     MatCardActions,
//     MatDatepickerModule,
//     MatNativeDateModule,
//     CommonModule,
//     MatProgressBarModule,

//     BrowserModule,
//     FormsModule,
//     ReactiveFormsModule,
//   ],
// })
// export class DocumentUploadComponent implements OnInit {
//   @ViewChild('fileInput') fileInput!: ElementRef;

//   uploadForm: FormGroup;
//   selectedFile: File | null = null;
//   previewUrl: string | null = null;
//   uploadProgress: number = 0;
//   isUploading: boolean = false;
//   uploadError: string | null = null;

//   constructor(
//     private fb: FormBuilder,
//     private documentService: DocumentService,
//     private router: Router,
//     private snackBar: MatSnackBar
//   ) {
//     this.uploadForm = this.fb.group({
//       title: ['', [Validators.required, Validators.maxLength(100)]],
//       description: ['', Validators.maxLength(500)],
//       tags: [''],
//       expiryDate: [null],
//     });
//   }

//   ngOnInit(): void {}

//   onFileSelected(event: Event): void {
//     const input = event.target as HTMLInputElement;

//     if (input.files && input.files.length > 0) {
//       const file = input.files[0];

//       // Check if file is a PDF
//       if (file.type !== 'application/pdf') {
//         this.uploadError = 'Only PDF files are allowed';
//         this.selectedFile = null;
//         this.previewUrl = null;
//         return;
//       }

//       // Check file size (limit to 10MB)
//       if (file.size > 10 * 1024 * 1024) {
//         this.uploadError = 'File size cannot exceed 10MB';
//         this.selectedFile = null;
//         this.previewUrl = null;
//         return;
//       }

//       this.selectedFile = file;
//       this.uploadError = null;

//       // Create preview URL
//       this.createPreview(file);
//     }
//   }

//   createPreview(file: File): void {
//     // For PDFs, we could either:
//     // 1. Show a generic PDF icon
//     // 2. Generate a thumbnail of the first page (more complex)

//     // For simplicity, we'll just set a placeholder
//     this.previewUrl = 'assets/images/pdf-preview.png';

//     // If you want to implement actual PDF preview:
//     // const reader = new FileReader();
//     // reader.onload = (e) => {
//     //   // Use PDF.js to render first page as preview
//     //   // This is more complex and requires PDF.js setup
//     // };
//     // reader.readAsArrayBuffer(file);
//   }

//   removeFile(): void {
//     this.selectedFile = null;
//     this.previewUrl = null;
//     this.uploadError = null;
//     this.fileInput.nativeElement.value = '';
//   }

//   uploadDocument(): void {
//     if (this.uploadForm.invalid || !this.selectedFile) {
//       return;
//     }

//     this.isUploading = true;
//     this.uploadProgress = 0;

//     const formData = new FormData();
//     formData.append('file', this.selectedFile);
//     formData.append('title', this.uploadForm.get('title')?.value);
//     formData.append(
//       'description',
//       this.uploadForm.get('description')?.value || ''
//     );

//     if (this.uploadForm.get('tags')?.value) {
//       const tags = this.uploadForm
//         .get('tags')
//         ?.value.split(',')
//         .map((tag: string) => tag.trim());
//       formData.append('tags', JSON.stringify(tags));
//     }

//     if (this.uploadForm.get('expiryDate')?.value) {
//       formData.append(
//         'expiryDate',
//         this.uploadForm.get('expiryDate')?.value.toISOString()
//       );
//     }

//     this.documentService.uploadDocument(formData).subscribe({
//       next: (event: any) => {
//         if (event.type === HttpEventType.UploadProgress) {
//           this.uploadProgress = Math.round((100 * event.loaded) / event.total);
//         } else if (event instanceof HttpResponse) {
//           this.isUploading = false;
//           this.snackBar.open('Document uploaded successfully', 'Close', {
//             duration: 3000,
//             horizontalPosition: 'center',
//             verticalPosition: 'bottom',
//           });
//           this.router.navigate(['/documents']);
//         }
//       },
//       error: (err) => {
//         this.isUploading = false;
//         this.uploadError =
//           err.error?.message ||
//           'Failed to upload document. Please try again later.';
//         this.snackBar.open(this.uploadError || '', 'Close', {
//           duration: 5000,
//           horizontalPosition: 'center',
//           verticalPosition: 'bottom',
//           panelClass: ['error-snackbar'],
//         });
//       },
//     });
//   }

//   onDragOver(event: DragEvent): void {
//     event.preventDefault();
//     event.stopPropagation();
//   }

//   onDragLeave(event: DragEvent): void {
//     event.preventDefault();
//     event.stopPropagation();
//   }

//   onDrop(event: DragEvent): void {
//     event.preventDefault();
//     event.stopPropagation();

//     if (event.dataTransfer && event.dataTransfer.files.length > 0) {
//       const file = event.dataTransfer.files[0];

//       if (file.type === 'application/pdf') {
//         this.selectedFile = file;
//         this.uploadError = null;
//         this.createPreview(file);

//         // Update form value for display
//         this.uploadForm.patchValue({
//           title: file.name.replace('.pdf', ''),
//         });
//       } else {
//         this.uploadError = 'Only PDF files are allowed';
//       }
//     }
//   }

//   onSubmit(): void {
//     this.uploadDocument();
//   }

//   cancel(): void {
//     this.router.navigate(['/documents']);
//   }
// }

// // // document-upload.component.ts
// // import { Component, EventEmitter, Output } from '@angular/core';

// // @Component({
// //   selector: 'app-document-upload',
// //   template: `
// //     <div class="document-upload">
// //       <div
// //         class="upload-zone"
// //         [class.dragging]="isDragging"
// //         (dragover)="onDragOver($event)"
// //         (dragleave)="onDragLeave($event)"
// //         (drop)="onDrop($event)"
// //       >
// //         <div class="upload-icon">
// //           <i class="fa fa-cloud-upload"></i>
// //         </div>
// //         <h3>Drop your PDF file here</h3>
// //         <p>or</p>
// //         <label for="file-input" class="file-input-label">Browse Files</label>
// //         <input
// //           type="file"
// //           id="file-input"
// //           accept=".pdf"
// //           (change)="onFileSelected($event)"
// //         />
// //       </div>

// //       <div class="upload-status" *ngIf="uploadedFile">
// //         <div class="file-info">
// //           <i class="fa fa-file-pdf-o"></i>
// //           <span>{{ uploadedFile.name }}</span>
// //         </div>
// //         <div class="file-actions">
// //           <button class="preview-btn">Preview</button>
// //           <button class="remove-btn" (click)="removeFile()">Remove</button>
// //         </div>
// //       </div>
// //     </div>
// //   `,
// //   styles: [
// //     `
// //       .document-upload {
// //         padding: 20px;
// //       }
// //       .upload-zone {
// //         border: 2px dashed #ccc;
// //         border-radius: 8px;
// //         padding: 40px;
// //         text-align: center;
// //         cursor: pointer;
// //         transition: background-color 0.3s;
// //       }
// //       .upload-zone.dragging {
// //         background-color: #f0f8ff;
// //         border-color: #007bff;
// //       }
// //       .upload-icon {
// //         font-size: 48px;
// //         color: #ccc;
// //         margin-bottom: 10px;
// //       }
// //       .upload-zone h3 {
// //         margin: 0;
// //         color: #333;
// //       }
// //       .upload-zone p {
// //         margin: 10px 0;
// //         color: #666;
// //       }
// //       #file-input {
// //         display: none;
// //       }
// //       .file-input-label {
// //         display: inline-block;
// //         padding: 10px 20px;
// //         background-color: #007bff;
// //         color: white;
// //         border-radius: 4px;
// //         cursor: pointer;
// //       }
// //       .upload-status {
// //         margin-top: 20px;
// //         padding: 15px;
// //         background-color: #f9f9f9;
// //         border-radius: 4px;
// //         display: flex;
// //         justify-content: space-between;
// //         align-items: center;
// //       }
// //       .file-info {
// //         display: flex;
// //         align-items: center;
// //       }
// //       .file-info i {
// //         font-size: 24px;
// //         color: #ff5722;
// //         margin-right: 10px;
// //       }
// //       .file-actions button {
// //         margin-left: 10px;
// //         padding: 6px 12px;
// //         border: none;
// //         border-radius: 4px;
// //         cursor: pointer;
// //       }
// //       .preview-btn {
// //         background-color: #007bff;
// //         color: white;
// //       }
// //       .remove-btn {
// //         background-color: #f44336;
// //         color: white;
// //       }
// //     `,
// //   ],
// // })
// // export class DocumentUploadComponent {
// //   @Output() fileUploaded = new EventEmitter<File>();

// //   isDragging = false;
// //   uploadedFile: File | null = null;

// //   onDragOver(event: DragEvent) {
// //     event.preventDefault();
// //     event.stopPropagation();
// //     this.isDragging = true;
// //   }

// //   onDragLeave(event: DragEvent) {
// //     event.preventDefault();
// //     event.stopPropagation();
// //     this.isDragging = false;
// //   }

// //   onDrop(event: DragEvent) {
// //     event.preventDefault();
// //     event.stopPropagation();
// //     this.isDragging = false;

// //     const files = event.dataTransfer?.files;
// //     if (files && files.length > 0) {
// //       this.processFile(files[0]);
// //     }
// //   }

// //   onFileSelected(event: Event) {
// //     const input = event.target as HTMLInputElement;
// //     if (input.files && input.files.length > 0) {
// //       this.processFile(input.files[0]);
// //     }
// //   }

// //   processFile(file: File) {
// //     if (file.type === 'application/pdf') {
// //       this.uploadedFile = file;
// //       this.fileUploaded.emit(file);
// //     } else {
// //       alert('Please upload a PDF file.');
// //     }
// //   }

// //   removeFile() {
// //     this.uploadedFile = null;
// //   }
// // }

// document-upload.component.ts
import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Output } from '@angular/core';
import { DocumentService } from '../../services/document.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-document-upload',
  template: `
    <div class="document-upload">
      <div
        class="upload-zone"
        [class.dragging]="isDragging"
        (dragover)="onDragOver($event)"
        (dragleave)="onDragLeave($event)"
        (drop)="onDrop($event)"
      >
        <div class="upload-icon">
          <i class="fa fa-cloud-upload"></i>
        </div>
        <h3>Drop your PDF file here</h3>
        <p>or</p>
        <label for="file-input" class="file-input-label">Browse Files</label>
        <input
          type="file"
          id="file-input"
          accept=".pdf"
          (change)="onFileSelected($event)"
        />
      </div>

      <div class="upload-status" *ngIf="uploadedFile">
        <div class="file-info">
          <i class="fa fa-file-pdf-o"></i>
          <span>{{ uploadedFile!.name }}</span>
        </div>
        <div class="file-actions">
          <button class="preview-btn" (click)="previewFile()">Preview</button>
          <button class="remove-btn" (click)="removeFile()">Remove</button>
        </div>
      </div>
    </div>
  `,
  styles: [
    `
      .document-upload {
        padding: 20px;
      }
      .upload-zone {
        border: 2px dashed #ccc;
        border-radius: 8px;
        padding: 40px;
        text-align: center;
        cursor: pointer;
        transition: background-color 0.3s;
      }
      .upload-zone.dragging {
        background-color: #f0f8ff;
        border-color: #007bff;
      }
      .upload-icon {
        font-size: 48px;
        color: #ccc;
        margin-bottom: 10px;
      }
      .upload-zone h3 {
        margin: 0;
        color: #333;
      }
      .upload-zone p {
        margin: 10px 0;
        color: #666;
      }
      #file-input {
        display: none;
      }
      .file-input-label {
        display: inline-block;
        padding: 10px 20px;
        background-color: #007bff;
        color: white;
        border-radius: 4px;
        cursor: pointer;
      }
      .upload-status {
        margin-top: 20px;
        padding: 15px;
        background-color: #f9f9f9;
        border-radius: 4px;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      .file-info {
        display: flex;
        align-items: center;
      }
      .file-info i {
        font-size: 24px;
        color: #ff5722;
        margin-right: 10px;
      }
      .file-actions button {
        margin-left: 10px;
        padding: 6px 12px;
        border: none;
        border-radius: 4px;
        cursor: pointer;
      }
      .preview-btn {
        background-color: #007bff;
        color: white;
      }
      .remove-btn {
        background-color: #f44336;
        color: white;
      }
    `,
  ],
  imports: [CommonModule],
})
export class DocumentUploadComponent {
  @Output() fileUploaded = new EventEmitter<File>();

  constructor(
    private documentService: DocumentService,
    private router: Router
  ) {}

  isDragging = false;
  uploadedFile: File | null = null;

  // processFile(file: File) {
  //   if (file.type === 'application/pdf') {
  //     this.uploadedFile = file;
  //     this.documentService.setFile(file);
  //     this.router.navigate(['/documents/view']); // navigate to viewer
  //   } else {
  //     alert('Only PDF files are allowed');
  //   }
  // }

  // processFile(file: File) {
  //   if (file.type === 'application/pdf') {
  //     this.uploadedFile = file;

  //     this.documentService.uploadDocument(file).subscribe({
  //       next: (doc: any) => {
  //         this.router.navigate(['/documents', doc.id]); // Navigate using ID
  //       },
  //       error: (err) => {
  //         console.error('Upload failed', err);
  //         alert('Failed to upload document');
  //       },
  //     });
  //   } else {
  //     alert('Only PDF files are allowed');
  //   }
  // }

  // this.documentService.uploadFile(file).subscribe((doc) => {
  //   this.router.navigate(['/documents', doc.id]);
  // });

  onDragOver(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = true;
  }

  onDragLeave(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = false;
  }

  onDrop(event: DragEvent) {
    event.preventDefault();
    event.stopPropagation();
    this.isDragging = false;

    const files = event.dataTransfer?.files;
    if (files && files.length > 0) {
      this.processFile(files[0], true);
    }
  }

  // onFileSelected(event: Event) {
  //   const input = event.target as HTMLInputElement;
  //   if (input.files && input.files.length > 0) {
  //     this.processFile(input.files[0]);
  //   }
  // }

  // In your DocumentUploadComponent:
  onFileSelected(event: Event) {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      const file = input.files[0];
      this.processFile(file); // Handle the file
      // After processing, navigate to the document view page
      // this.router.navigate(['/documents', document]);
    }
  }

  // processFile(file: File) {
  //   if (file.type === 'application/pdf') {
  //     this.uploadedFile = file;
  //     this.fileUploaded.emit(file);
  //   } else {
  //     alert('Please upload a PDF file.');
  //   }
  // }

  processFile(file: File, triggerSignMode: boolean = false) {
    if (file.type === 'application/pdf') {
      this.uploadedFile = file;

      this.documentService.uploadDocument(file).subscribe({
        next: (doc: any) => {
          const targetUrl = triggerSignMode
            ? ['/documents', doc.id, { sign: true }]
            : ['/documents', doc.id];

          this.router.navigate(targetUrl);
        },
        error: (err) => {
          console.error('Upload failed', err);
          alert('Failed to upload document');
        },
      });
    } else {
      alert('Only PDF files are allowed');
    }
  }

  previewFile() {
    if (this.uploadedFile) {
      const fileURL = URL.createObjectURL(this.uploadedFile);
      const newTab = window.open(fileURL, '_blank');
      // Optional: revoke the object URL after the tab is loaded
      if (newTab) {
        newTab.onload = () => URL.revokeObjectURL(fileURL);
      }
    }
  }

  removeFile() {
    this.uploadedFile = null;
  }

  logout(): void {
    localStorage.removeItem('token');
  }

  // To automatically scroll to the signature tools:
  // if (q['sign']) {
  //   this.signingMode = true;
  //   this.loadSignatures();

  //   setTimeout(() => {
  //     document
  //       .querySelector('.signature-panel')
  //       ?.scrollIntoView({ behavior: 'smooth' });
  //   }, 500);
  // }
}

// // File: app/components/document-list/document-list.component.ts
// import { Component, OnInit } from '@angular/core';
// import { Router } from '@angular/router';
// import { Observable } from 'rxjs';
// import { Document } from '../../models/document.model';
// import { DocumentService } from '../../services/document.service';
// import { AuthService } from '../../services/auth.service';
// import { CommonModule } from '@angular/common';
// import { FormsModule } from '@angular/forms';

// @Component({
//   selector: 'app-document-list',
//   templateUrl: './document-list.component.html',
//   styleUrls: ['./document-list.component.scss'],
//   imports: [CommonModule, FormsModule],
// })
// export class DocumentListComponent implements OnInit {
//   documents: Document[] = [];
//   loading = true;
//   error: string | null = null;

//   // Filters
//   statusFilter: string = 'all'; // 'all', 'pending', 'signed'
//   sortBy: string = 'uploadedAt'; // 'uploadedAt', 'filename'
//   sortDirection: string = 'desc'; // 'asc', 'desc'

//   constructor(
//     private documentService: DocumentService,
//     private authService: AuthService,
//     private router: Router
//   ) {}

//   ngOnInit(): void {
//     this.loadDocuments();
//   }

//   loadDocuments(): void {
//     this.loading = true;
//     this.error = null;

//     this.documentService.getDocuments().subscribe({
//       next: (documents) => {
//         this.documents = documents;
//         this.applyFilters();
//         this.loading = false;
//       },
//       error: (err) => {
//         console.error('Error loading documents', err);
//         this.error = 'Failed to load documents. Please try again later.';
//         this.loading = false;
//       },
//     });
//   }

//   applyFilters(): void {
//     let filteredDocs = [...this.documents];

//     // Apply status filter
//     if (this.statusFilter !== 'all') {
//       filteredDocs = filteredDocs.filter(
//         (doc) => doc.status === this.statusFilter
//       );
//     }

//     // Apply sorting
//     filteredDocs.sort((a, b) => {
//       let valueA, valueB;

//       if (this.sortBy === 'uploadedAt') {
//         valueA = a.uploadedAt ? new Date(a.uploadedAt).getTime() : 0;
//         valueB = b.uploadedAt ? new Date(b.uploadedAt).getTime() : 0;
//       } else {
//         valueA = a.filename ? a.filename.toLowerCase() : '';
//         valueB = b.filename ? b.filename.toLowerCase() : '';
//       }

//       const direction = this.sortDirection === 'asc' ? 1 : -1;

//       if (valueA < valueB) return -1 * direction;
//       if (valueA > valueB) return 1 * direction;
//       return 0;
//     });

//     this.documents = filteredDocs;
//   }

//   viewDocument(document: Document): void {
//     this.router.navigate(['/documents', document.id]);
//   }

//   signDocument(document: Document): void {
//     this.router.navigate(['/documents', document.id, 'sign']);
//   }

//   downloadDocument(document: Document, event: Event): void {
//     event.stopPropagation();
//     this.documentService.downloadDocument(document.id!).subscribe({
//       next: (blob) => {
//         const url = window.URL.createObjectURL(blob);
//         const link = window.document.createElement('a');
//         link.href = url;
//         link.download = document.filename ?? 'download.pdf';
//         link.click();
//         window.URL.revokeObjectURL(url);
//       },
//       error: (err) => {
//         console.error('Error downloading document', err);
//         this.error = 'Failed to download document. Please try again later.';
//       },
//     });
//   }

//   deleteDocument(document: Document, event: Event): void {
//     event.stopPropagation();
//     if (confirm(`Are you sure you want to delete ${document.filename}?`)) {
//       this.documentService.deleteDocument(document.id!.toString()).subscribe({
//         next: () => {
//           this.documents = this.documents.filter((d) => d.id !== document.id);
//         },
//         error: (err) => {
//           console.error('Error deleting document', err);
//           this.error = 'Failed to delete document. Please try again later.';
//         },
//       });
//     }
//   }

//   uploadNewDocument(): void {
//     this.router.navigate(['/documents/upload']);
//   }

//   // Filter and sort handlers
//   onStatusFilterChange(status: string): void {
//     this.statusFilter = status;
//     this.applyFilters();
//   }

//   onSortChange(sortField: string): void {
//     if (this.sortBy === sortField) {
//       this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
//     } else {
//       this.sortBy = sortField;
//       this.sortDirection = 'desc';
//     }
//     this.applyFilters();
//   }

//   getStatusClass(status: string | undefined): string {
//     switch (status) {
//       case 'signed':
//         return 'status-signed';
//       case 'pending':
//         return 'status-pending';
//       default:
//         return 'status-default';
//     }
//   }

//   refreshDocuments(): void {
//     this.loadDocuments();
//   }
// }

// // document-list.component.ts
// import { Component, OnInit, ViewChild } from '@angular/core';
// import { MatPaginator, MatPaginatorModule } from '@angular/material/paginator';
// import { MatTableDataSource, MatTableModule } from '@angular/material/table';
// import { MatSnackBar } from '@angular/material/snack-bar';
// import { DocumentService } from '../../services/document.service';
// import { MatLabel } from '@angular/material/form-field';
// import { MatIcon } from '@angular/material/icon';
// import { MatCard } from '@angular/material/card';
// import { MatSpinner } from '@angular/material/progress-spinner';
// import { RouterModule } from '@angular/router';
// import { CommonModule } from '@angular/common';

// interface Document {
//   id: string;
//   name: string;
//   uploadDate: Date;
//   status: string;
//   size: number;
// }

// @Component({
//   imports: [
//     RouterModule,
//     MatTableModule,
//     MatIcon,
//     MatCard,
//     MatSpinner,
//     RouterModule,
//     CommonModule,
//     MatPaginatorModule,
//   ],
//   template: `
//     <div class="document-list-container">
//       <div class="header-row">
//         <h2>My Documents</h2>
//         <button
//           mat-raised-button
//           color="primary"
//           routerLink="/documents/upload"
//         >
//           <mat-icon>upload_file</mat-icon>
//           Upload Document
//         </button>
//       </div>

//       <mat-card>
//         <div class="loading-container" *ngIf="isLoading">
//           <mat-spinner diameter="40"></mat-spinner>
//         </div>

//         <div
//           *ngIf="!isLoading && dataSource.data.length === 0"
//           class="no-documents"
//         >
//           <mat-icon>description</mat-icon>
//           <p>No documents found</p>
//           <button
//             mat-raised-button
//             color="primary"
//             routerLink="/documents/upload"
//           >
//             Upload Your First Document
//           </button>
//         </div>

//         <div *ngIf="!isLoading && dataSource.data.length > 0">
//           <table mat-table [dataSource]="dataSource">
//             <!-- Document Name Column -->
//             <ng-container matColumnDef="name">
//               <th mat-header-cell *matHeaderCellDef>Document Name</th>
//               <td mat-cell *matCellDef="let document">
//                 <a [routerLink]="['/documents', document.id]">{{
//                   document.name
//                 }}</a>
//               </td>
//             </ng-container>

//             <!-- Upload Date Column -->
//             <ng-container matColumnDef="uploadDate">
//               <th mat-header-cell *matHeaderCellDef>Upload Date</th>
//               <td mat-cell *matCellDef="let document">
//                 {{ document.uploadDate | date }}
//               </td>
//             </ng-container>

//             <!-- Status Column -->
//             <ng-container matColumnDef="status">
//               <th mat-header-cell *matHeaderCellDef>Status</th>
//               <td mat-cell *matCellDef="let document">
//                 <span [ngClass]="'status-' + document.status.toLowerCase()">{{
//                   document.status
//                 }}</span>
//               </td>
//             </ng-container>

//             <!-- Size Column -->
//             <ng-container matColumnDef="size">
//               <th mat-header-cell *matHeaderCellDef>Size</th>
//               <td mat-cell *matCellDef="let document">
//                 {{ formatFileSize(document.size) }}
//               </td>
//             </ng-container>

//             <!-- Actions Column -->
//             <ng-container matColumnDef="actions">
//               <th mat-header-cell *matHeaderCellDef>Actions</th>
//               <td mat-cell *matCellDef="let document">
//                 <button
//                   mat-icon-button
//                   [routerLink]="['/documents', document.id]"
//                   matTooltip="View document"
//                 >
//                   <mat-icon>visibility</mat-icon>
//                 </button>
//                 <button
//                   mat-icon-button
//                   (click)="deleteDocument(document)"
//                   matTooltip="Delete document"
//                 >
//                   <mat-icon>delete</mat-icon>
//                 </button>
//               </td>
//             </ng-container>

//             <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
//             <tr mat-row *matRowDef="let row; columns: displayedColumns"></tr>
//           </table>

//           <mat-paginator
//             [pageSizeOptions]="[5, 10, 25]"
//             showFirstLastButtons
//           ></mat-paginator>
//         </div>
//       </mat-card>
//     </div>
//   `,

//   styles: [
//     `
//       .document-list-container {
//         padding: 20px;
//       }
//       .header-row {
//         display: flex;
//         justify-content: space-between;
//         align-items: center;
//         margin-bottom: 20px;
//       }
//       .loading-container {
//         display: flex;
//         justify-content: center;
//         padding: 20px;
//       }
//       .no-documents {
//         display: flex;
//         flex-direction: column;
//         align-items: center;
//         padding: 40px 0;
//       }
//       .no-documents mat-icon {
//         font-size: 48px;
//         width: 48px;
//         height: 48px;
//         color: #9e9e9e;
//       }
//       .no-documents p {
//         margin: 16px 0;
//         color: #757575;
//       }
//       table {
//         width: 100%;
//       }
//       .status-signed {
//         color: #4caf50;
//       }
//       .status-pending {
//         color: #ff9800;
//       }
//       .status-draft {
//         color: #9e9e9e;
//       }
//     `,
//   ],
// })
// export class DocumentListComponent implements OnInit {
//   displayedColumns: string[] = [
//     'name',
//     'uploadDate',
//     'status',
//     'size',
//     'actions',
//   ];
//   dataSource = new MatTableDataSource<Document>([]);
//   isLoading = false;

//   @ViewChild(MatPaginator) paginator!: MatPaginator;

//   constructor(
//     private documentService: DocumentService,
//     private snackBar: MatSnackBar
//   ) {}

//   ngOnInit(): void {
//     this.loadDocuments();
//   }

//   ngAfterViewInit() {
//     this.dataSource.paginator = this.paginator;
//   }

//   loadDocuments(): void {
//     this.isLoading = true;
//     this.documentService.getDocuments().subscribe({
//       next: (documents) => {
//         this.dataSource.data = documents;
//         this.isLoading = false;
//       },
//       error: (error) => {
//         this.isLoading = false;
//         this.snackBar.open('Failed to load documents', 'Close', {
//           duration: 5000,
//           panelClass: ['error-snackbar'],
//         });
//       },
//     });
//   }

//   deleteDocument(document: Document): void {
//     if (confirm(`Are you sure you want to delete ${document.name}?`)) {
//       this.documentService.deleteDocument(document.id).subscribe({
//         next: () => {
//           this.dataSource.data = this.dataSource.data.filter(
//             (d) => d.id !== document.id
//           );
//           this.snackBar.open('Document deleted successfully', 'Close', {
//             duration: 3000,
//             panelClass: ['success-snackbar'],
//           });
//         },
//         error: (error) => {
//           this.snackBar.open('Failed to delete document', 'Close', {
//             duration: 5000,
//             panelClass: ['error-snackbar'],
//           });
//         },
//       });
//     }
//   }

//   formatFileSize(bytes: number): string {
//     if (bytes === 0) return '0 Bytes';
//     const k = 1024;
//     const sizes = ['Bytes', 'KB', 'MB', 'GB'];
//     const i = Math.floor(Math.log(bytes) / Math.log(k));
//     return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
//   }
// }

import { Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator, MatPaginatorModule } from '@angular/material/paginator';
import { MatTableDataSource, MatTableModule } from '@angular/material/table';
import { MatSnackBar } from '@angular/material/snack-bar';
import { DocumentService } from '../../services/document.service';
import { MatLabel } from '@angular/material/form-field';
import { MatIcon } from '@angular/material/icon';
import { MatCard } from '@angular/material/card';
import { MatSpinner } from '@angular/material/progress-spinner';
import { RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Document } from '../../models/document.model'; // Import the Document model from your models folder

@Component({
  imports: [
    RouterModule,
    MatTableModule,
    MatIcon,
    MatCard,
    MatSpinner,
    RouterModule,
    CommonModule,
    MatPaginatorModule,
  ],
  template: `
    <div class="document-list-container">
      <div class="header-row">
        <h2>My Documents</h2>
        <button
          mat-raised-button
          color="primary"
          routerLink="/documents/upload"
        >
          <mat-icon>upload_file</mat-icon>
          Upload Document
        </button>
      </div>

      <mat-card>
        <div class="loading-container" *ngIf="isLoading">
          <mat-spinner diameter="40"></mat-spinner>
        </div>

        <div
          *ngIf="!isLoading && dataSource.data.length === 0"
          class="no-documents"
        >
          <mat-icon>description</mat-icon>
          <p>No documents found</p>
          <button
            mat-raised-button
            color="primary"
            routerLink="/documents/upload"
          >
            Upload Your First Document
          </button>
        </div>

        <div *ngIf="!isLoading && dataSource.data.length > 0">
          <table mat-table [dataSource]="dataSource">
            <!-- Document Name Column -->
            <ng-container matColumnDef="name">
              <th mat-header-cell *matHeaderCellDef>Document Name</th>
              <td mat-cell *matCellDef="let document">
                <a [routerLink]="['/documents', document.id]">{{
                  document.name
                }}</a>
              </td>
            </ng-container>

            <!-- Upload Date Column -->
            <ng-container matColumnDef="uploadDate">
              <th mat-header-cell *matHeaderCellDef>Upload Date</th>
              <td mat-cell *matCellDef="let document">
                {{ document.uploadDate | date }}
              </td>
            </ng-container>

            <!-- Status Column -->
            <ng-container matColumnDef="status">
              <th mat-header-cell *matHeaderCellDef>Status</th>
              <td mat-cell *matCellDef="let document">
                <span [ngClass]="'status-' + document.status.toLowerCase()">{{
                  document.status
                }}</span>
              </td>
            </ng-container>

            <!-- Size Column -->
            <ng-container matColumnDef="size">
              <th mat-header-cell *matHeaderCellDef>Size</th>
              <td mat-cell *matCellDef="let document">
                {{ formatFileSize(document.size) }}
              </td>
            </ng-container>

            <!-- Actions Column -->
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>Actions</th>
              <td mat-cell *matCellDef="let document">
                <button
                  mat-icon-button
                  [routerLink]="['/documents', document.id]"
                  matTooltip="View document"
                >
                  <mat-icon>visibility</mat-icon>
                </button>
                <button
                  mat-icon-button
                  (click)="deleteDocument(document)"
                  matTooltip="Delete document"
                >
                  <mat-icon>delete</mat-icon>
                </button>
              </td>
            </ng-container>

            <tr mat-header-row *matHeaderRowDef="displayedColumns"></tr>
            <tr mat-row *matRowDef="let row; columns: displayedColumns"></tr>
          </table>

          <mat-paginator
            [pageSizeOptions]="[5, 10, 25]"
            showFirstLastButtons
          ></mat-paginator>
        </div>
      </mat-card>
    </div>
  `,

  styles: [
    `
      .document-list-container {
        padding: 20px;
      }
      .header-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
      }
      .loading-container {
        display: flex;
        justify-content: center;
        padding: 20px;
      }
      .no-documents {
        display: flex;
        flex-direction: column;
        align-items: center;
        padding: 40px 0;
      }
      .no-documents mat-icon {
        font-size: 48px;
        width: 48px;
        height: 48px;
        color: #9e9e9e;
      }
      .no-documents p {
        margin: 16px 0;
        color: #757575;
      }
      table {
        width: 100%;
      }
      .status-signed {
        color: #4caf50;
      }
      .status-pending {
        color: #ff9800;
      }
      .status-draft {
        color: #9e9e9e;
      }
    `,
  ],
})
export class DocumentListComponent implements OnInit {
  displayedColumns: string[] = [
    'name',
    'uploadDate',
    'status',
    'size',
    'actions',
  ];
  dataSource = new MatTableDataSource<Document>([]);
  isLoading = false;

  @ViewChild(MatPaginator) paginator!: MatPaginator;

  constructor(
    private documentService: DocumentService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.loadDocuments();
  }

  ngAfterViewInit() {
    this.dataSource.paginator = this.paginator;
  }

  loadDocuments(): void {
    this.isLoading = true;
    this.documentService.getDocuments().subscribe({
      next: (documents) => {
        this.dataSource.data = documents;
        this.isLoading = false;
      },
      error: (error) => {
        this.isLoading = false;
        this.snackBar.open('Failed to load documents', 'Close', {
          duration: 5000,
          panelClass: ['error-snackbar'],
        });
      },
    });
  }

  deleteDocument(document: Document): void {
    if (confirm(`Are you sure you want to delete ${document.filename}?`)) {
      this.documentService.deleteDocument(document.id!.toString()).subscribe({
        next: () => {
          this.dataSource.data = this.dataSource.data.filter(
            (d) => d.id !== document.id
          );
          this.snackBar.open('Document deleted successfully', 'Close', {
            duration: 3000,
            panelClass: ['success-snackbar'],
          });
        },
        error: (error) => {
          this.snackBar.open('Failed to delete document', 'Close', {
            duration: 5000,
            panelClass: ['error-snackbar'],
          });
        },
      });
    }
  }

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

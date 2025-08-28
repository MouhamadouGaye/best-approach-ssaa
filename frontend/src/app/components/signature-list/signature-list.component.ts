import { Component, OnInit, OnDestroy, NgModule } from '@angular/core';
import { Router, RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatPaginator, PageEvent } from '@angular/material/paginator';
import { Observable, Subject } from 'rxjs';
import { takeUntil, finalize } from 'rxjs/operators';

import { SignatureService } from '../../services/signature.service';

import { Signature } from '../../models/signature.model';
import { NotificationService } from '../../services/notification.service';
import { ConfirmDialogComponent } from '../confirn-dialog/confirn-dialog.component';
import { MatCard, MatCardModule } from '@angular/material/card';
import { CommonModule } from '@angular/common';
import { MatIcon } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { FormsModule } from '@angular/forms';
import { MatSpinner } from '@angular/material/progress-spinner';
import { BrowserModule } from '@angular/platform-browser';
import { MatMenuModule } from '@angular/material/menu';

@Component({
  selector: 'app-signature-list',
  templateUrl: './signature-list.component.html',
  styleUrls: ['./signature-list.component.scss'],
  imports: [
    CommonModule,
    MatCardModule,
    MatCard,
    MatIcon,
    RouterModule, // if you're using routerLink
    FormsModule,
    BrowserModule,
    MatMenuModule,
    MatPaginator,
    MatSpinner,
    MatFormFieldModule,
  ],
})
export class SignatureListComponent implements OnInit, OnDestroy {
  signatures: Signature[] = [];
  filteredSignatures: Signature[] = [];
  selectedSignatureId: string | null = null;
  isLoading = false;
  hasError = false;
  errorMessage = 'Failed to load signatures. Please try again.';

  // Pagination
  currentPage = 0;
  pageSize = 16;
  totalItems = 0;
  totalPages = 0;

  // Search
  searchQuery = '';

  private destroy$ = new Subject<void>();

  constructor(
    private signatureService: SignatureService,
    private router: Router,
    private dialog: MatDialog,
    private notificationService: NotificationService
  ) {}

  ngOnInit(): void {
    this.loadSignatures();
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  loadSignatures(): void {
    this.isLoading = true;
    this.hasError = false;

    this.signatureService
      .getSignatures()
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => (this.isLoading = false))
      )
      .subscribe(
        (response) => {
          this.signatures = (response as any).items;
          this.filteredSignatures = this.signatures;
          this.totalPages = Math.ceil(this.totalItems / this.pageSize);
        },
        (error) => {
          console.error('Error loading signatures:', error);
          this.hasError = true;
          this.errorMessage = 'Failed to load signatures. Please try again.';
        }
      );
  }

  applyFilter(): void {
    if (!this.searchQuery) {
      this.filteredSignatures = this.signatures;
      return;
    }

    const query = this.searchQuery.toLowerCase().trim();
    this.filteredSignatures = this.signatures.filter((signature) =>
      signature.username.toLowerCase().includes(query)
    );
  }

  onPageChange(event: PageEvent): void {
    this.currentPage = event.pageIndex;
    this.pageSize = event.pageSize;
    this.loadSignatures();
  }

  selectSignature(signature: Signature): void {
    // this.selectedSignatureId = signature.id;
    this.selectedSignatureId = signature.id?.toString() || null;
    // Additional logic when selecting a signature, if needed
  }

  editSignature(signature: Signature): void {
    this.router.navigate(['/signatures/edit', signature.id]);
  }

  setAsDefault(signature: Signature): void {
    this.isLoading = true;

    this.signatureService
      .setDefaultSignature(signature.id!.toString())
      .pipe(
        takeUntil(this.destroy$),
        finalize(() => (this.isLoading = false))
      )
      .subscribe(
        () => {
          // Update local data to reflect changes
          this.signatures = this.signatures.map((sig) => ({
            ...sig,
            isDefault: sig.id === signature.id,
          }));
          this.applyFilter(); // Update filtered signatures

          this.notificationService.showSuccess(
            'Default signature updated successfully'
          );
        },
        (error) => {
          console.error('Error setting default signature:', error);
          this.notificationService.showError('Failed to set default signature');
        }
      );
  }

  deleteSignature(signature: Signature): void {
    const dialogRef = this.dialog.open(ConfirmDialogComponent, {
      width: '400px',
      data: {
        title: 'Delete Signature',
        message: `Are you sure you want to delete the signature "${signature.user}"? This action cannot be undone.`,
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        confirmButtonColor: 'warn',
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      if (result) {
        this.isLoading = true;

        this.signatureService
          .deleteSignature(signature.id!.toString())
          .pipe(
            takeUntil(this.destroy$),
            finalize(() => (this.isLoading = false))
          )
          .subscribe(
            () => {
              // Remove from local arrays
              this.signatures = this.signatures.filter(
                (sig) => sig.id !== signature.id
              );
              this.applyFilter(); // Update filtered signatures

              if (this.signatures.length === 0 && this.currentPage > 0) {
                this.currentPage--;
                this.loadSignatures();
              }

              this.notificationService.showSuccess(
                'Signature deleted successfully'
              );
            },
            (error) => {
              console.error('Error deleting signature:', error);
              this.notificationService.showError('Failed to delete signature');
            }
          );
      }
    });
  }
}

// // File: app/components/signature-list/signature-list.component.ts
// import { Component, OnInit, OnDestroy, NgModule } from '@angular/core';
// import { MatDialog } from '@angular/material/dialog';
// import { MatSnackBar } from '@angular/material/snack-bar';
// import { Subject } from 'rxjs';
// import { takeUntil } from 'rxjs/operators';
// import { SignatureService } from '../../services/signature.service';
// import { Signature } from '../../models/signature.model';
// import {
//   MatCard,
//   MatCardActions,
//   MatCardContent,
//   MatCardHeader,
//   MatCardTitle,
// } from '@angular/material/card';
// import { MatIcon } from '@angular/material/icon';
// import { FormsModule } from '@angular/forms';
// import { MatSpinner } from '@angular/material/progress-spinner';
// import { SignaturePadComponent } from '../signature-pad/signature-pad.component';
// import {
//   MatFormField,
//   MatFormFieldModule,
//   MatLabel,
// } from '@angular/material/form-field';

// @Component({
//   selector: 'app-signature-list',
//   templateUrl: './signature-list.component.html',
//   styleUrls: ['./signature-list.component.scss'],
//   imports: [
//     MatCard,
//     MatCardHeader,
//     MatCardTitle,
//     MatIcon,
//     MatCardContent,
//     FormsModule,
//     MatSpinner,
//     SignaturePadComponent,
//     MatFormField,
//     MatFormFieldModule,
//     MatLabel,
//   ],
// })
// export class SignatureListComponent implements OnInit, OnDestroy {
//   signatures: Signature[] = [];
//   loading = false;
//   error: string | null = null;
//   selectedSignature: Signature | null = null;
//   showCreateSignature = false;

//   private unsubscribe$ = new Subject<void>();

//   constructor(
//     private signatureService: SignatureService,
//     private dialog: MatDialog,
//     private snackBar: MatSnackBar
//   ) {}

//   ngOnInit(): void {
//     this.loadSignatures();
//   }

//   ngOnDestroy(): void {
//     this.unsubscribe$.next();
//     this.unsubscribe$.complete();
//   }

//   loadSignatures(): void {
//     this.loading = true;
//     this.error = null;

//     this.signatureService
//       .getUserSignatures()
//       .pipe(takeUntil(this.unsubscribe$))
//       .subscribe({
//         next: (signatures) => {
//           this.signatures = signatures;
//           this.loading = false;

//           // If a signature was selected but removed, unselect it
//           if (
//             this.selectedSignature &&
//             !this.signatures.some((s) => s.id === this.selectedSignature?.id)
//           ) {
//             this.selectedSignature = null;
//           }
//         },
//         error: (err) => {
//           console.error('Error loading signatures', err);
//           this.error = 'Failed to load signatures. Please try again later.';
//           this.loading = false;
//         },
//       });
//   }

//   toggleCreateSignature(): void {
//     this.showCreateSignature = !this.showCreateSignature;
//     if (!this.showCreateSignature) {
//       this.selectedSignature = null;
//     }
//   }

//   onSignatureCreated(signatureData: string): void {
//     this.loading = true;

//     this.signatureService
//       .createSignature({
//         name: `Signature ${new Date().toLocaleDateString()}`,
//         dataUrl: signatureData,
//       })
//       .pipe(takeUntil(this.unsubscribe$))
//       .subscribe({
//         next: (signature) => {
//           this.signatures.push(signature);
//           this.loading = false;
//           this.showCreateSignature = false;
//           this.selectedSignature = signature;

//           this.snackBar.open('Signature created successfully', 'Close', {
//             duration: 3000,
//           });
//         },
//         error: (err) => {
//           console.error('Error creating signature', err);
//           this.error = 'Failed to create signature. Please try again later.';
//           this.loading = false;
//         },
//       });
//   }

//   selectSignature(signature: Signature): void {
//     this.selectedSignature = signature;
//   }

//   isSelected(signature: Signature): boolean {
//     return this.selectedSignature?.id === signature.id;
//   }

//   renameSignature(signature: Signature, newName: string): void {
//     if (!newName.trim() || newName === signature.name) {
//       return;
//     }

//     this.signatureService
//       .updateSignature({
//         ...signature,
//         name: newName.trim(),
//       })
//       .pipe(takeUntil(this.unsubscribe$))
//       .subscribe({
//         next: (updatedSignature) => {
//           const index = this.signatures.findIndex(
//             (s) => s.id === updatedSignature.id
//           );
//           if (index !== -1) {
//             this.signatures[index] = updatedSignature;
//           }

//           if (this.selectedSignature?.id === updatedSignature.id) {
//             this.selectedSignature = updatedSignature;
//           }

//           this.snackBar.open('Signature renamed successfully', 'Close', {
//             duration: 3000,
//           });
//         },
//         error: (err) => {
//           console.error('Error renaming signature', err);
//           this.snackBar.open('Failed to rename signature', 'Close', {
//             duration: 3000,
//           });
//         },
//       });
//   }

//   deleteSignature(signature: Signature, event: Event): void {
//     event.stopPropagation();

//     // Confirm deletion
//     const confirmed = confirm(
//       `Are you sure you want to delete the signature "${signature.name}"?`
//     );
//     if (!confirmed) {
//       return;
//     }

//     this.signatureService
//       .deleteSignature(signature.id)
//       .pipe(takeUntil(this.unsubscribe$))
//       .subscribe({
//         next: () => {
//           this.signatures = this.signatures.filter(
//             (s) => s.id !== signature.id
//           );

//           if (this.selectedSignature?.id === signature.id) {
//             this.selectedSignature = null;
//           }

//           this.snackBar.open('Signature deleted successfully', 'Close', {
//             duration: 3000,
//           });
//         },
//         error: (err) => {
//           console.error('Error deleting signature', err);
//           this.snackBar.open('Failed to delete signature', 'Close', {
//             duration: 3000,
//           });
//         },
//       });
//   }

//   setDefaultSignature(signature: Signature): void {
//     this.signatureService
//       .setDefaultSignature(signature.id)
//       .pipe(takeUntil(this.unsubscribe$))
//       .subscribe({
//         next: () => {
//           // Update the is_default flag
//           this.signatures.forEach((s) => {
//             s.isDefault = s.id === signature.id;
//           });

//           this.snackBar.open(
//             `"${signature.name}" set as default signature`,
//             'Close',
//             {
//               duration: 3000,
//             }
//           );
//         },
//         error: (err) => {
//           console.error('Error setting default signature', err);
//           this.snackBar.open('Failed to set default signature', 'Close', {
//             duration: 3000,
//           });
//         },
//       });
//   }
// }

// // signature-list.component.ts
// import { CommonModule } from '@angular/common';
// import { Component, EventEmitter, Input, Output } from '@angular/core';

// interface Signature {
//   id: number;
//   name: string;
//   dataUrl: string;
//   created: Date;
// }

// @Component({
//   selector: 'app-signature-list',
//   imports: [CommonModule],
//   template: `
//     <div class="signature-list">
//       <h3>Saved Signatures</h3>
//       <div class="signature-grid">
//         <div class="signature-item" *ngFor="let signature of signatures">
//           <div class="signature-preview">
//             <img [src]="signature.dataUrl" alt="Signature" />
//           </div>
//           <div class="signature-details">
//             <span class="signature-name">{{ signature.name }}</span>
//             <span class="signature-date">{{
//               signature.created | date : 'short'
//             }}</span>
//           </div>
//           <div class="signature-actions">
//             <button class="select-btn" (click)="selectSignature(signature)">
//               Use
//             </button>
//             <button class="delete-btn" (click)="deleteSignature(signature)">
//               Delete
//             </button>
//           </div>
//         </div>
//         <div class="signature-empty" *ngIf="signatures.length === 0">
//           <p>No saved signatures yet. Create one using the signature pad.</p>
//         </div>
//       </div>
//     </div>
//   `,
//   styles: [
//     `
//       .signature-list {
//         padding: 20px;
//         background-color: #f9f9f9;
//         border-radius: 8px;
//       }
//       .signature-grid {
//         display: grid;
//         grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
//         gap: 20px;
//         margin-top: 20px;
//       }
//       .signature-item {
//         background-color: white;
//         border-radius: 8px;
//         overflow: hidden;
//         box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
//       }
//       .signature-preview {
//         height: 120px;
//         display: flex;
//         align-items: center;
//         justify-content: center;
//         padding: 10px;
//         background-color: #f5f5f5;
//       }
//       .signature-preview img {
//         max-width: 100%;
//         max-height: 100%;
//       }
//       .signature-details {
//         padding: 10px;
//         border-top: 1px solid #eee;
//       }
//       .signature-name {
//         display: block;
//         font-weight: bold;
//         margin-bottom: 5px;
//       }
//       .signature-date {
//         font-size: 0.8rem;
//         color: #666;
//       }
//       .signature-actions {
//         display: flex;
//         border-top: 1px solid #eee;
//       }
//       .signature-actions button {
//         flex: 1;
//         padding: 8px;
//         border: none;
//         cursor: pointer;
//       }
//       .select-btn {
//         background-color: #4caf50;
//         color: white;
//       }
//       .delete-btn {
//         background-color: #f44336;
//         color: white;
//       }
//       .signature-empty {
//         grid-column: 1 / -1;
//         text-align: center;
//         padding: 20px;
//         background-color: #f0f0f0;
//         border-radius: 8px;
//       }
//     `,
//   ],
// })
// export class SignatureListComponent {
//   @Input() signatures: Signature[] = [];
//   @Output() signatureSelected = new EventEmitter<Signature>();
//   @Output() signatureDeleted = new EventEmitter<Signature>();

//   selectSignature(signature: Signature) {
//     this.signatureSelected.emit(signature);
//   }

//   deleteSignature(signature: Signature) {
//     this.signatureDeleted.emit(signature);
//   }
// }

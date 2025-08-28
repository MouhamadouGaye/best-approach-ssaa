// File: app/components/signature-pad/signature-pad.component.ts
import { CommonModule } from '@angular/common';
import { Component, OnInit, EventEmitter, Output } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { SignatureCanvasComponent } from '../signature-canvas/signature-canvas.component';
import { MatIcon } from '@angular/material/icon';

@Component({
  selector: 'app-signature-pad',
  templateUrl: './signature-pad.component.html',
  styleUrls: ['./signature-pad.component.scss'],
  imports: [CommonModule, SignatureCanvasComponent, MatIcon],
})
export class SignaturePadComponent implements OnInit {
  @Output() signatureCreated = new EventEmitter<string>();

  signatureDataUrl: string | null = null;
  showCanvas = false;

  constructor(private dialog: MatDialog) {}

  ngOnInit(): void {}

  toggleCanvas(): void {
    this.showCanvas = !this.showCanvas;
  }

  onSignatureCreated(dataUrl: string): void {
    this.signatureDataUrl = dataUrl;
    this.signatureCreated.emit(dataUrl);
    this.showCanvas = false;
  }

  clearSignature(): void {
    this.signatureDataUrl = null;
  }

  uploadSignature(event: Event): void {
    const input = event.target as HTMLInputElement;

    if (input.files && input.files.length > 0) {
      const file = input.files[0];

      if (file.type.startsWith('image/')) {
        const reader = new FileReader();

        reader.onload = (e) => {
          this.signatureDataUrl = e.target?.result as string;
          this.signatureCreated.emit(this.signatureDataUrl);
        };

        reader.readAsDataURL(file);
      }
    }
  }
}

// // // // signature-pad.component.ts
// // // import { Component, EventEmitter, Output } from '@angular/core';

// // // @Component({
// // //   selector: 'app-signature-pad',
// // //   template: `
// // //     <div class="signature-pad">
// // //       <h3>Sign Here</h3>
// // //       <div class="signature-options">
// // //         <div class="option">
// // //           <button
// // //             (click)="activeOption = 'draw'"
// // //             [class.active]="activeOption === 'draw'"
// // //           >
// // //             Draw Signature
// // //           </button>
// // //         </div>
// // //         <div class="option">
// // //           <button
// // //             (click)="activeOption = 'type'"
// // //             [class.active]="activeOption === 'type'"
// // //           >
// // //             Type Signature
// // //           </button>
// // //         </div>
// // //         <div class="option">
// // //           <button
// // //             (click)="activeOption = 'upload'"
// // //             [class.active]="activeOption === 'upload'"
// // //           >
// // //             Upload Signature
// // //           </button>
// // //         </div>
// // //       </div>

// // //       <div class="signature-content" [ngSwitch]="activeOption">
// // //         <div *ngSwitchCase="'draw'">
// // //           <app-signature-canvas
// // //             (signatureSaved)="onSignatureSaved($event)"
// // //           ></app-signature-canvas>
// // //         </div>
// // //         <div *ngSwitchCase="'type'">
// // //           <div class="type-signature">
// // //             <input
// // //               type="text"
// // //               placeholder="Type your name"
// // //               [(ngModel)]="typedSignature"
// // //             />
// // //             <div class="signature-preview" *ngIf="typedSignature">
// // //               <p class="signature-text">{{ typedSignature }}</p>
// // //             </div>
// // //             <button (click)="saveTypedSignature()" [disabled]="!typedSignature">
// // //               Save
// // //             </button>
// // //           </div>
// // //         </div>
// // //         <div *ngSwitchCase="'upload'">
// // //           <div class="upload-signature">
// // //             <input
// // //               type="file"
// // //               (change)="onFileSelected($event)"
// // //               accept="image/*"
// // //             />
// // //             <div class="signature-preview" *ngIf="uploadedSignature">
// // //               <img [src]="uploadedSignature" alt="Uploaded signature" />
// // //             </div>
// // //           </div>
// // //         </div>
// // //       </div>
// // //     </div>
// // //   `,
// // //   styles: [
// // //     `
// // //       .signature-pad {
// // //         background-color: #f9f9f9;
// // //         padding: 20px;
// // //         border-radius: 8px;
// // //         box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
// // //       }
// // //       .signature-options {
// // //         display: flex;
// // //         margin-bottom: 20px;
// // //       }
// // //       .option {
// // //         flex: 1;
// // //         margin-right: 10px;
// // //       }
// // //       .option:last-child {
// // //         margin-right: 0;
// // //       }
// // //       .option button {
// // //         width: 100%;
// // //         padding: 10px;
// // //         background-color: #eee;
// // //         border: 1px solid #ddd;
// // //         border-radius: 4px;
// // //         cursor: pointer;
// // //       }
// // //       .option button.active {
// // //         background-color: #007bff;
// // //         color: white;
// // //         border-color: #0069d9;
// // //       }
// // //       .type-signature,
// // //       .upload-signature {
// // //         margin-top: 20px;
// // //       }
// // //       input[type='text'] {
// // //         width: 100%;
// // //         padding: 10px;
// // //         margin-bottom: 10px;
// // //         border: 1px solid #ddd;
// // //         border-radius: 4px;
// // //       }
// // //       .signature-preview {
// // //         margin: 15px 0;
// // //         padding: 10px;
// // //         border: 1px dashed #ccc;
// // //         min-height: 100px;
// // //         display: flex;
// // //         align-items: center;
// // //         justify-content: center;
// // //       }
// // //       .signature-text {
// // //         font-family: 'Brush Script MT', cursive;
// // //         font-size: 32px;
// // //         color: #333;
// // //       }
// // //       button {
// // //         padding: 8px 16px;
// // //         background-color: #4caf50;
// // //         color: white;
// // //         border: none;
// // //         border-radius: 4px;
// // //         cursor: pointer;
// // //       }
// // //       button:disabled {
// // //         background-color: #cccccc;
// // //         cursor: not-allowed;
// // //       }
// // //       img {
// // //         max-width: 100%;
// // //         max-height: 100px;
// // //       }
// // //     `,
// // //   ],
// // // })
// // // export class SignaturePadComponent {
// // //   @Output() signatureCreated = new EventEmitter<string>();

// // //   activeOption: 'draw' | 'type' | 'upload' = 'draw';
// // //   typedSignature: string = '';
// // //   uploadedSignature: string | null = null;

// // //   onSignatureSaved(signatureDataUrl: string) {
// // //     this.signatureCreated.emit(signatureDataUrl);
// // //   }

// // //   saveTypedSignature() {
// // //     if (this.typedSignature) {
// // //       // Create a canvas to render the typed signature
// // //       const canvas = document.createElement('canvas');
// // //       const context = canvas.getContext('2d');
// // //       canvas.width = 400;
// // //       canvas.height = 200;

// // //       if (context) {
// // //         context.fillStyle = 'white';
// // //         context.fillRect(0, 0, canvas.width, canvas.height);
// // //         context.font = '32px "Brush Script MT", cursive';
// // //         context.fillStyle = 'black';
// // //         context.textAlign = 'center';
// // //         context.textBaseline = 'middle';
// // //         context.fillText(
// // //           this.typedSignature,
// // //           canvas.width / 2,
// // //           canvas.height / 2
// // //         );

// // //         const dataUrl = canvas.toDataURL('image/png');
// // //         this.signatureCreated.emit(dataUrl);
// // //       }
// // //     }
// // //   }

// // //   onFileSelected(event: Event) {
// // //     const input = event.target as HTMLInputElement;
// // //     if (input.files && input.files[0]) {
// // //       const file = input.files[0];
// // //       const reader = new FileReader();

// // //       reader.onload = (e) => {
// // //         this.uploadedSignature = e.target?.result as string;
// // //         this.signatureCreated.emit(this.uploadedSignature);
// // //       };

// // //       reader.readAsDataURL(file);
// // //     }
// // //   }
// // // }

// // // signature-pad.component.ts
// // import { Component, EventEmitter, Output } from '@angular/core';
// // import { SignatureCanvasComponent } from '../signature-canvas/signature-canvas.component';
// // import { CommonModule } from '@angular/common';
// // import { FormsModule } from '@angular/forms';

// // @Component({
// //   selector: 'app-signature-pad',
// //   template: `
// //     <div class="signature-pad">
// //       <h3>Sign Here</h3>
// //       <div class="signature-options">
// //         <div class="option">
// //           <button
// //             (click)="activeOption = 'draw'"
// //             [class.active]="activeOption === 'draw'"
// //           >
// //             Draw Signature
// //           </button>
// //         </div>
// //         <div class="option">
// //           <button
// //             (click)="activeOption = 'type'"
// //             [class.active]="activeOption === 'type'"
// //           >
// //             Type Signature
// //           </button>
// //         </div>
// //         <div class="option">
// //           <button
// //             (click)="activeOption = 'upload'"
// //             [class.active]="activeOption === 'upload'"
// //           >
// //             Upload Signature
// //           </button>
// //         </div>
// //       </div>

// //       <div class="signature-content" [ngSwitch]="activeOption">
// //         <div *ngSwitchCase="'draw'">
// //           <app-signature-canvas
// //             (signatureSaved)="onSignatureSaved($event)"
// //           ></app-signature-canvas>
// //         </div>
// //         <div *ngSwitchCase="'type'">
// //           <div class="type-signature">
// //             <input
// //               type="text"
// //               placeholder="Type your name"
// //               [(ngModel)]="typedSignature"
// //             />
// //             <div class="signature-preview" *ngIf="typedSignature">
// //               <p class="signature-text">{{ typedSignature }}</p>
// //             </div>
// //             <button (click)="saveTypedSignature()" [disabled]="!typedSignature">
// //               Save
// //             </button>
// //           </div>
// //         </div>
// //         <div *ngSwitchCase="'upload'">
// //           <div class="upload-signature">
// //             <input
// //               type="file"
// //               (change)="onFileSelected($event)"
// //               accept="image/*"
// //             />
// //             <div class="signature-preview" *ngIf="uploadedSignature">
// //               <img [src]="uploadedSignature" alt="Uploaded signature" />
// //             </div>
// //           </div>
// //         </div>
// //       </div>
// //     </div>
// //   `,
// //   styles: [
// //     `
// //       .signature-pad {
// //         background-color: #f9f9f9;
// //         padding: 20px;
// //         border-radius: 8px;
// //         box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
// //       }
// //       .signature-options {
// //         display: flex;
// //         margin-bottom: 20px;
// //       }
// //       .option {
// //         flex: 1;
// //         margin-right: 10px;
// //       }
// //       .option:last-child {
// //         margin-right: 0;
// //       }
// //       .option button {
// //         width: 100%;
// //         padding: 10px;
// //         background-color: #eee;
// //         border: 1px solid #ddd;
// //         border-radius: 4px;
// //         cursor: pointer;
// //       }
// //       .option button.active {
// //         background-color: #007bff;
// //         color: white;
// //         border-color: #0069d9;
// //       }
// //       .type-signature,
// //       .upload-signature {
// //         margin-top: 20px;
// //       }
// //       input[type='text'] {
// //         width: 100%;
// //         padding: 10px;
// //         margin-bottom: 10px;
// //         border: 1px solid #ddd;
// //         border-radius: 4px;
// //       }
// //       .signature-preview {
// //         margin: 15px 0;
// //         padding: 10px;
// //         border: 1px dashed #ccc;
// //         min-height: 100px;
// //         display: flex;
// //         align-items: center;
// //         justify-content: center;
// //       }
// //       .signature-text {
// //         font-family: 'Brush Script MT', cursive;
// //         font-size: 32px;
// //         color: #333;
// //       }
// //       button {
// //         padding: 8px 16px;
// //         background-color: #4caf50;
// //         color: white;
// //         border: none;
// //         border-radius: 4px;
// //         cursor: pointer;
// //       }
// //       button:disabled {
// //         background-color: #cccccc;
// //         cursor: not-allowed;
// //       }
// //       img {
// //         max-width: 100%;
// //         max-height: 100px;
// //       }
// //     `,
// //   ],
// //   imports: [SignatureCanvasComponent, CommonModule, FormsModule],
// // })
// // export class SignaturePadComponent {
// //   @Output() signatureCreated = new EventEmitter<string>();

// //   activeOption: 'draw' | 'type' | 'upload' = 'draw';
// //   typedSignature: string = '';
// //   uploadedSignature: string | null = null;

// //   onSignatureSaved(signatureDataUrl: string) {
// //     this.signatureCreated.emit(signatureDataUrl);
// //   }

// //   saveTypedSignature() {
// //     if (this.typedSignature) {
// //       // Create a canvas to render the typed signature
// //       const canvas = document.createElement('canvas');
// //       const context = canvas.getContext('2d');
// //       canvas.width = 400;
// //       canvas.height = 200;

// //       if (context) {
// //         context.fillStyle = 'white';
// //         context.fillRect(0, 0, canvas.width, canvas.height);
// //         context.font = '32px "Brush Script MT", cursive';
// //         context.fillStyle = 'black';
// //         context.textAlign = 'center';
// //         context.textBaseline = 'middle';
// //         context.fillText(
// //           this.typedSignature,
// //           canvas.width / 2,
// //           canvas.height / 2
// //         );

// //         const dataUrl = canvas.toDataURL('image/png');
// //         this.signatureCreated.emit(dataUrl);
// //       }
// //     }
// //   }

// //   onFileSelected(event: Event) {
// //     const input = event.target as HTMLInputElement;
// //     if (input.files && input.files[0]) {
// //       const file = input.files[0];
// //       const reader = new FileReader();

// //       reader.onload = (e) => {
// //         this.uploadedSignature = e.target?.result as string;
// //         this.signatureCreated.emit(this.uploadedSignature);
// //       };

// //       reader.readAsDataURL(file);
// //     }
// //   }
// // }

// import {
//   Component,
//   ElementRef,
//   EventEmitter,
//   Output,
//   ViewChild,
//   AfterViewInit,
// } from '@angular/core';
// import { CommonModule } from '@angular/common';
// import { MatButtonModule } from '@angular/material/button';
// import { MatIconModule } from '@angular/material/icon';

// @Component({
//   selector: 'app-signature-pad',
//   standalone: true,
//   imports: [CommonModule, MatButtonModule, MatIconModule],
//   template: `
//     <div class="signature-pad-container">
//       <canvas #signatureCanvas class="signature-canvas"></canvas>

//       <div class="signature-controls">
//         <button mat-raised-button color="warn" (click)="clearSignature()">
//           <mat-icon>delete</mat-icon> Clear
//         </button>

//         <button mat-raised-button color="primary" (click)="saveSignature()">
//           <mat-icon>save</mat-icon> Save Signature
//         </button>
//       </div>
//     </div>
//   `,
//   styles: [
//     `
//       .signature-pad-container {
//         display: flex;
//         flex-direction: column;
//         width: 100%;
//         padding: 15px;
//       }

//       .signature-canvas {
//         border: 1px solid #ccc;
//         border-radius: 4px;
//         width: 100%;
//         height: 200px;
//         background-color: #fff;
//         margin-bottom: 15px;
//       }

//       .signature-controls {
//         display: flex;
//         justify-content: space-between;
//       }
//     `,
//   ],
// })
// export class SignaturePadComponent implements AfterViewInit {
//   @ViewChild('signatureCanvas') signatureCanvas!: ElementRef<HTMLCanvasElement>;
//   @Output() signatureCreated = new EventEmitter<string>();

//   private canvas!: HTMLCanvasElement;
//   private ctx!: CanvasRenderingContext2D;
//   private drawing = false;

//   ngAfterViewInit(): void {
//     this.initializeCanvas();
//   }

//   private initializeCanvas(): void {
//     this.canvas = this.signatureCanvas.nativeElement;
//     this.ctx = this.canvas.getContext('2d')!;

//     // Set canvas dimensions
//     this.canvas.width = this.canvas.offsetWidth;
//     this.canvas.height = this.canvas.offsetHeight;

//     // Set canvas styles
//     this.ctx.lineWidth = 2;
//     this.ctx.lineCap = 'round';
//     this.ctx.strokeStyle = '#000';

//     // Add event listeners
//     this.canvas.addEventListener('mousedown', this.startDrawing.bind(this));
//     this.canvas.addEventListener('mousemove', this.draw.bind(this));
//     this.canvas.addEventListener('mouseup', this.stopDrawing.bind(this));
//     this.canvas.addEventListener('mouseout', this.stopDrawing.bind(this));

//     // Touch support
//     this.canvas.addEventListener(
//       'touchstart',
//       this.startDrawingTouch.bind(this)
//     );
//     this.canvas.addEventListener('touchmove', this.drawTouch.bind(this));
//     this.canvas.addEventListener('touchend', this.stopDrawing.bind(this));
//   }

//   private startDrawing(e: MouseEvent): void {
//     this.drawing = true;
//     this.ctx.beginPath();
//     const rect = this.canvas.getBoundingClientRect();
//     this.ctx.moveTo(e.clientX - rect.left, e.clientY - rect.top);
//   }

//   private startDrawingTouch(e: TouchEvent): void {
//     e.preventDefault();
//     if (e.touches.length > 0) {
//       this.drawing = true;
//       this.ctx.beginPath();
//       const rect = this.canvas.getBoundingClientRect();
//       const touch = e.touches[0];
//       this.ctx.moveTo(touch.clientX - rect.left, touch.clientY - rect.top);
//     }
//   }

//   private draw(e: MouseEvent): void {
//     if (!this.drawing) return;
//     const rect = this.canvas.getBoundingClientRect();
//     this.ctx.lineTo(e.clientX - rect.left, e.clientY - rect.top);
//     this.ctx.stroke();
//   }

//   private drawTouch(e: TouchEvent): void {
//     e.preventDefault();
//     if (!this.drawing || e.touches.length === 0) return;
//     const rect = this.canvas.getBoundingClientRect();
//     const touch = e.touches[0];
//     this.ctx.lineTo(touch.clientX - rect.left, touch.clientY - rect.top);
//     this.ctx.stroke();
//   }

//   private stopDrawing(): void {
//     this.drawing = false;
//   }

//   clearSignature(): void {
//     this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
//   }

//   saveSignature(): void {
//     // Emit the signature as a data URL
//     const signatureDataUrl = this.canvas.toDataURL('image/png');
//     this.signatureCreated.emit(signatureDataUrl);
//   }
// }

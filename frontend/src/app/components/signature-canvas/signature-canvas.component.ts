// File: app/components/signature-canvas/signature-canvas.component.ts
import {
  Component,
  ElementRef,
  EventEmitter,
  Input,
  OnInit,
  Output,
  ViewChild,
  AfterViewInit,
} from '@angular/core';

@Component({
  selector: 'app-signature-canvas',
  templateUrl: './signature-canvas.component.html',
  styleUrls: ['./signature-canvas.component.scss'],
})
export class SignatureCanvasComponent implements AfterViewInit {
  @ViewChild('canvas') canvas!: ElementRef<HTMLCanvasElement>;
  @Output() signatureCreated = new EventEmitter<string>();
  @Input() width = 500;
  @Input() height = 200;

  private ctx!: CanvasRenderingContext2D;
  private isDrawing = false;
  private lastX = 0;
  private lastY = 0;

  ngAfterViewInit(): void {
    const canvas = this.canvas.nativeElement;
    canvas.width = this.width;
    canvas.height = this.height;

    this.ctx = canvas.getContext('2d')!;
    this.ctx.lineWidth = 2;
    this.ctx.lineCap = 'round';
    this.ctx.strokeStyle = '#000000';

    // Initial clear
    this.clear();
  }

  onMouseDown(e: MouseEvent): void {
    this.isDrawing = true;
    const rect = this.canvas.nativeElement.getBoundingClientRect();
    this.lastX = e.clientX - rect.left;
    this.lastY = e.clientY - rect.top;
  }

  onMouseMove(e: MouseEvent): void {
    if (!this.isDrawing) return;

    const rect = this.canvas.nativeElement.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    this.ctx.beginPath();
    this.ctx.moveTo(this.lastX, this.lastY);
    this.ctx.lineTo(x, y);
    this.ctx.stroke();

    this.lastX = x;
    this.lastY = y;
  }

  onMouseUp(): void {
    this.isDrawing = false;
    // Emit the signature data
    this.signatureCreated.emit(this.canvas.nativeElement.toDataURL());
  }

  onMouseLeave(): void {
    this.isDrawing = false;
  }

  // Touch support
  onTouchStart(e: TouchEvent): void {
    e.preventDefault();
    const rect = this.canvas.nativeElement.getBoundingClientRect();
    this.isDrawing = true;
    this.lastX = e.touches[0].clientX - rect.left;
    this.lastY = e.touches[0].clientY - rect.top;
  }

  onTouchMove(e: TouchEvent): void {
    e.preventDefault();
    if (!this.isDrawing) return;

    const rect = this.canvas.nativeElement.getBoundingClientRect();
    const x = e.touches[0].clientX - rect.left;
    const y = e.touches[0].clientY - rect.top;

    this.ctx.beginPath();
    this.ctx.moveTo(this.lastX, this.lastY);
    this.ctx.lineTo(x, y);
    this.ctx.stroke();

    this.lastX = x;
    this.lastY = y;
  }

  onTouchEnd(e: TouchEvent): void {
    e.preventDefault();
    this.isDrawing = false;
    // Emit the signature data
    this.signatureCreated.emit(this.canvas.nativeElement.toDataURL());
  }

  clear(): void {
    this.ctx.fillStyle = '#FFFFFF';
    this.ctx.fillRect(
      0,
      0,
      this.canvas.nativeElement.width,
      this.canvas.nativeElement.height
    );
  }

  save(): void {
    const dataUrl = this.canvas.nativeElement.toDataURL();
    this.signatureCreated.emit(dataUrl);
  }
}

// // signature-canvas.component.ts
// import {
//   Component,
//   ElementRef,
//   EventEmitter,
//   Input,
//   OnInit,
//   Output,
//   ViewChild,
// } from '@angular/core';
// import SignaturePad from 'signature_pad';

// @Component({
//   selector: 'app-signature-canvas',
//   template: `
//     <div class="signature-canvas-container">
//       <canvas #signatureCanvas class="signature-canvas"></canvas>
//       <div class="signature-controls">
//         <button class="clear-btn" (click)="clear()">Clear</button>
//         <button class="save-btn" (click)="save()">Save</button>
//       </div>
//     </div>
//   `,
//   styles: [
//     `
//       .signature-canvas-container {
//         display: flex;
//         flex-direction: column;
//         border: 1px solid #ccc;
//         border-radius: 4px;
//         overflow: hidden;
//       }
//       .signature-canvas {
//         width: 100%;
//         height: 200px;
//         background-color: #fff;
//       }
//       .signature-controls {
//         display: flex;
//         justify-content: space-between;
//         padding: 10px;
//         background-color: #f5f5f5;
//       }
//       button {
//         padding: 8px 16px;
//         border: none;
//         border-radius: 4px;
//         cursor: pointer;
//       }
//       .clear-btn {
//         background-color: #f44336;
//         color: white;
//       }
//       .save-btn {
//         background-color: #4caf50;
//         color: white;
//       }
//     `,
//   ],
// })
// export class SignatureCanvasComponent implements OnInit {
//   @ViewChild('signatureCanvas') signatureCanvasElement: ElementRef;
//   @Output() signatureSaved = new EventEmitter<string>();

//   private signaturePad: SignaturePad;

//   ngOnInit() {}

//   ngAfterViewInit() {
//     this.initializeSignaturePad();
//   }

//   private initializeSignaturePad() {
//     const canvas = this.signatureCanvasElement.nativeElement;
//     this.signaturePad = new SignaturePad(canvas);
//     this.resizeCanvas();

//     // Handle window resize to adjust canvas size
//     window.addEventListener('resize', () => this.resizeCanvas());
//   }

//   private resizeCanvas() {
//     const canvas = this.signatureCanvasElement.nativeElement;
//     const ratio = Math.max(window.devicePixelRatio || 1, 1);
//     canvas.width = canvas.offsetWidth * ratio;
//     canvas.height = canvas.offsetHeight * ratio;
//     canvas.getContext('2d').scale(ratio, ratio);
//     this.signaturePad.clear(); // Clear the canvas
//   }

//   clear() {
//     this.signaturePad.clear();
//   }

//   save() {
//     if (!this.signaturePad.isEmpty()) {
//       const signatureDataUrl = this.signaturePad.toDataURL();
//       this.signatureSaved.emit(signatureDataUrl);
//     }
//   }
// }

// // signature-canvas.component.ts
// import {
//   Component,
//   ElementRef,
//   EventEmitter,
//   Input,
//   OnInit,
//   Output,
//   ViewChild,
// } from '@angular/core';
// import SignaturePad from 'signature_pad';

// // To install signature_pad:
// // npm install signature_pad

// @Component({
//   selector: 'app-signature-canvas',
//   template: `
//     <div class="signature-canvas-container">
//       <canvas #signatureCanvas class="signature-canvas"></canvas>
//       <div class="signature-controls">
//         <button class="clear-btn" (click)="clear()">Clear</button>
//         <button class="save-btn" (click)="save()">Save</button>
//       </div>
//     </div>
//   `,
//   styles: [
//     `
//       .signature-canvas-container {
//         display: flex;
//         flex-direction: column;
//         border: 1px solid #ccc;
//         border-radius: 4px;
//         overflow: hidden;
//       }
//       .signature-canvas {
//         width: 100%;
//         height: 200px;
//         background-color: #fff;
//       }
//       .signature-controls {
//         display: flex;
//         justify-content: space-between;
//         padding: 10px;
//         background-color: #f5f5f5;
//       }
//       button {
//         padding: 8px 16px;
//         border: none;
//         border-radius: 4px;
//         cursor: pointer;
//       }
//       .clear-btn {
//         background-color: #f44336;
//         color: white;
//       }
//       .save-btn {
//         background-color: #4caf50;
//         color: white;
//       }
//     `,
//   ],
// })
// export class SignatureCanvasComponent implements OnInit {
//   @ViewChild('signatureCanvas') signatureCanvasElement!: ElementRef;
//   @Output() signatureSaved = new EventEmitter<string>();

//   private signaturePad!: SignaturePad;

//   ngOnInit() {}

//   ngAfterViewInit() {
//     this.initializeSignaturePad();
//   }

//   private initializeSignaturePad() {
//     const canvas = this.signatureCanvasElement.nativeElement;
//     this.signaturePad = new SignaturePad(canvas);
//     this.resizeCanvas();

//     // Handle window resize to adjust canvas size
//     window.addEventListener('resize', () => this.resizeCanvas());
//   }

//   private resizeCanvas() {
//     const canvas = this.signatureCanvasElement.nativeElement;
//     const ratio = Math.max(window.devicePixelRatio || 1, 1);
//     canvas.width = canvas.offsetWidth * ratio;
//     canvas.height = canvas.offsetHeight * ratio;
//     canvas.getContext('2d').scale(ratio, ratio);
//     this.signaturePad.clear(); // Clear the canvas
//   }

//   clear() {
//     this.signaturePad.clear();
//   }

//   save() {
//     if (!this.signaturePad.isEmpty()) {
//       const signatureDataUrl = this.signaturePad.toDataURL();
//       this.signatureSaved.emit(signatureDataUrl);
//     }
//   }
// }

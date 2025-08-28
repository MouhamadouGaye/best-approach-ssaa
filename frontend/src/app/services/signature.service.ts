// import { Injectable } from '@angular/core';
// import { BehaviorSubject, Observable, of } from 'rxjs';
// import { Signature } from '../models/signature.model';

// export interface SignatureData {
//   dataUrl: string;
//   date: Date;
//   signatureType: string;
// }

// @Injectable({
//   providedIn: 'root',
// })
// export class SignatureService {
//   private signatureSubject = new BehaviorSubject<SignatureData | null>(null);
//   private temporarySignature: SignatureData | null = null;

//   constructor() {
//     // Check if signature exists in local storage on service initialization
//     this.loadSavedSignature();
//   }

//   /**
//    * Get the current signature as an observable
//    */
//   getSignature(): Observable<SignatureData | null> {
//     return this.signatureSubject.asObservable();
//   }

//   /**
//    * Get the current signature value directly
//    */
//   getCurrentSignature(): SignatureData | null {
//     return this.signatureSubject.value;
//   }

//   /**
//    * Save a new signature
//    * @param dataUrl - The signature data URL (base64 encoded image)
//    * @param signatureType - The type of signature (draw, type, or image)
//    * @param save - Whether to save the signature permanently
//    */
//   saveSignature(
//     dataUrl: string,
//     signatureType: string,
//     save: boolean = true
//   ): Observable<SignatureData> {
//     const signatureData: SignatureData = {
//       dataUrl,
//       date: new Date(),
//       signatureType,
//     };

//     if (save) {
//       // Save to local storage for persistence
//       localStorage.setItem('userSignature', JSON.stringify(signatureData));
//       this.signatureSubject.next(signatureData);
//     } else {
//       // Just store temporarily (don't persist to storage)
//       this.temporarySignature = signatureData;
//     }
//     return of(signatureData);
//   }

//   /**
//    * Apply the temporary signature and make it permanent
//    */
//   applyTemporarySignature(): void {
//     if (this.temporarySignature) {
//       localStorage.setItem(
//         'userSignature',
//         JSON.stringify(this.temporarySignature)
//       );
//       this.signatureSubject.next(this.temporarySignature);
//       this.temporarySignature = null;
//     }
//   }

//   /**
//    * Clear the current signature
//    */
//   clearSignature(): void {
//     localStorage.removeItem('userSignature');
//     this.signatureSubject.next(null);
//     this.temporarySignature = null;
//   }

//   /**
//    * Clear the temporary signature without applying it
//    */
//   clearTemporarySignature(): void {
//     this.temporarySignature = null;
//   }

//   /**
//    * Get the temporary signature
//    */
//   getTemporarySignature(): SignatureData | null {
//     return this.temporarySignature;
//   }

//   /**
//    * Load a saved signature from local storage
//    */
//   private loadSavedSignature(): void {
//     const savedSignature = localStorage.getItem('userSignature');
//     if (savedSignature) {
//       try {
//         const signatureData = JSON.parse(savedSignature) as SignatureData;
//         // Convert string date back to Date object
//         signatureData.date = new Date(signatureData.date);
//         this.signatureSubject.next(signatureData);
//       } catch (error) {
//         console.error('Error loading saved signature:', error);
//         this.clearSignature();
//       }
//     }
//   }

//   /**
//    * Apply a signature to a PDF document
//    * @param pdfBytes - The PDF document bytes
//    * @param position - The position coordinates for the signature
//    * @param page - The page number to apply the signature to
//    * @returns Promise with the signed PDF bytes
//    */
//   async applySignatureToPdf(
//     pdfBytes: Uint8Array,
//     position: { x: number; y: number; width: number; height: number },
//     page: number
//   ): Promise<Uint8Array> {
//     // This is a placeholder for PDF manipulation logic
//     // You would typically use a PDF library like pdf-lib or integrate with a backend service

//     // For demo purposes, we're just returning the original PDF
//     // In a real implementation, you would insert the signature image at the specified position
//     console.log('Applying signature to PDF at:', position, 'on page:', page);

//     return pdfBytes;
//   }

//   /**
//    * Convert a signature to the appropriate format for PDF insertion
//    * @param signature - The signature data
//    * @returns formatted signature data ready for PDF insertion
//    */
//   prepareSignatureForPdf(signature: SignatureData): string {
//     // In a real implementation, you might need to format the signature data
//     // This could involve stripping the data URL prefix or converting formats
//     return signature.dataUrl;
//   }
// }

// import { Injectable } from '@angular/core';
// import { HttpClient } from '@angular/common/http';
// import { Observable } from 'rxjs';
// import { environment } from '../envirennements/environnement';

// export interface Signature {
//   id: string;
//   dataUrl: string;
//   name: string;
//   created: Date;
// }

// @Injectable({
//   providedIn: 'root',
// })
// export class SignatureService {
//   private apiUrl = `${environment.apiUrl}/signatures`;

//   constructor(private http: HttpClient) {}

//   // Fixed to return Observable<Signature[]>
//   getSignatures(): Observable<Signature[]> {
//     return this.http.get<Signature[]>(this.apiUrl);
//   }

//   // Fixed to return Observable<Signature>
//   saveSignature(name: string, signatureData: string): Observable<Signature> {
//     return this.http.post<Signature>(this.apiUrl, {
//       name,
//       dataUrl: signatureData,
//     });
//   }

//   deleteSignature(id: string): Observable<void> {
//     return this.http.delete<void>(`${this.apiUrl}/${id}`);
//   }
// }

import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, of } from 'rxjs';

export interface SignatureData {
  id: string; // Unique ID for multiple signatures
  dataUrl: string;
  date: Date;
  signatureType: string;
  totalItems: number;
}

const LOCAL_STORAGE_KEY = 'userSignatures';

@Injectable({
  providedIn: 'root',
})
export class SignatureService {
  private signaturesSubject = new BehaviorSubject<SignatureData[]>([]);
  private temporarySignature: SignatureData | null = null;
  // constructor(private http: HttpClient){}

  constructor(private http: HttpClient) {
    this.loadSignaturesFromStorage();
  }

  /**
   * Observable stream of all signatures
   */
  getSignatures(): Observable<SignatureData[]> {
    return this.signaturesSubject.asObservable();
  }

  // getSignatures(
  //   page: number,
  //   size: number,
  //   query: string
  // ): Observable<SignatureData> {
  //   const params = new HttpParams()
  //     .set('page', page.toString())
  //     .set('size', size.toString())
  //     .set('query', query);

  //   return this.http.get<SignatureData>('/api/signatures', { params });
  // }

  /**
   * Get current list of saved signatures
   */
  getCurrentSignatures(): SignatureData[] {
    return this.signaturesSubject.value;
  }

  /**
   * Save a new signature
   */
  saveSignature(
    dataUrl: string,
    signatureType: string,
    save: boolean = true
  ): Observable<SignatureData> {
    const signatureData: SignatureData = {
      id: this.generateUniqueId(),
      dataUrl,
      date: new Date(),
      signatureType,
      totalItems: 0,
    };

    if (save) {
      const updated = [...this.signaturesSubject.value, signatureData];
      this.persistSignatures(updated);
      this.signaturesSubject.next(updated);
    } else {
      this.temporarySignature = signatureData;
    }

    return of(signatureData);
  }

  setDefaultSignature(id: string): Observable<void> {
    return this.http.post<void>(`/api/signatures/${id}/default`, {});
  }

  /**
   * Use the temporary signature and store it
   */
  applyTemporarySignature(): void {
    if (this.temporarySignature) {
      const updated = [
        ...this.signaturesSubject.value,
        this.temporarySignature,
      ];
      this.persistSignatures(updated);
      this.signaturesSubject.next(updated);
      this.temporarySignature = null;
    }
  }

  /**
   * Remove a saved signature
   */

  deleteSignature(
    id: string
  ): Observable<{ items: SignatureData[]; totalItems: number }> {
    const updated = this.signaturesSubject.value.filter((sig) => sig.id !== id);
    this.persistSignatures(updated);
    this.signaturesSubject.next(updated);
    return of({ items: updated, totalItems: updated.length });
  }

  /**
   * Clear all saved signatures
   */
  clearAllSignatures(): void {
    localStorage.removeItem(LOCAL_STORAGE_KEY);
    this.signaturesSubject.next([]);
  }

  /**
   * Get a temporary signature
   */
  getTemporarySignature(): SignatureData | null {
    return this.temporarySignature;
  }

  /**
   * Prepare signature for PDF use
   */
  prepareSignatureForPdf(signature: SignatureData): string {
    return signature.dataUrl; // You could strip "data:image/png;base64," if needed
  }

  /**
   * Apply signature to a PDF (placeholder)
   */
  async applySignatureToPdf(
    pdfBytes: Uint8Array,
    position: { x: number; y: number; width: number; height: number },
    page: number
  ): Promise<Uint8Array> {
    // TODO: Replace with real PDF-lib or backend signing
    console.log('Applying signature to PDF:', position, 'on page', page);
    return pdfBytes;
  }

  // -----------------------------
  // Internal Helpers
  // -----------------------------

  private persistSignatures(signatures: SignatureData[]) {
    const toSave = signatures.map((sig) => ({
      ...sig,
      date: sig.date.toISOString(),
    }));
    localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(toSave));
  }

  private loadSignaturesFromStorage(): void {
    const saved = localStorage.getItem(LOCAL_STORAGE_KEY);
    if (saved) {
      try {
        const parsed = JSON.parse(saved) as SignatureData[];
        const formatted = parsed.map((sig) => ({
          ...sig,
          date: new Date(sig.date),
        }));
        this.signaturesSubject.next(formatted);
      } catch (err) {
        console.error('Failed to parse saved signatures:', err);
        this.clearAllSignatures();
      }
    }
  }

  private generateUniqueId(): string {
    return `sig_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
  }
}

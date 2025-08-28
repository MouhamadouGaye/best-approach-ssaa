import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Document } from '../models/document.model';
import { SignaturePosition } from '../models/signature-position.model';
import { environment } from '../envirennements/environnement';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root',
})
export class DocumentService {
  private uploadedFile: File | null = null;

  // Make this public since your DocumentViewerComponent accesses it directly
  apiUrl = `${environment.apiUrl}/documents`;

  constructor(private http: HttpClient, private authService: AuthService) {}

  setFile(file: File) {
    this.uploadedFile = file;
  }

  getFile(): File | null {
    return this.uploadedFile;
  }

  // uploadDocument(formData: FormData): Observable<Document> {
  //   return this.http.post<Document>(`${this.apiUrl}/upload`, formData);
  // }
  // uploadDocument(file: File): Observable<Document> {
  //   const formData = new FormData();
  //   formData.append('file', file);
  //   return this.http.post<Document>(`${this.apiUrl}/upload`, formData);
  // }

  // uploadDocument(file: File): Observable<Document> {
  //   const formData = new FormData();
  //   formData.append('file', file);

  //   const headers = new HttpHeaders({
  //     Authorization: `Bearer ${localStorage.getItem('auth_token') || ''}`,
  //   });

  //   return this.http.post<Document>(`${this.apiUrl}/upload`, formData, {
  //     headers,
  //   });
  // }

  uploadDocument(file: File): Observable<Document> {
    const formData = new FormData();
    formData.append('file', file);

    const headers = new HttpHeaders({
      Authorization: `Bearer ${this.authService.token}`,
    });

    return this.http.post<Document>(`${this.apiUrl}/upload`, formData, {
      headers,
    });
  }

  // getDocuments(): Observable<Document[]> {
  //   return this.http.get<Document[]>(this.apiUrl);
  // }

  getDocuments(): Observable<Document[]> {
    const headers = new HttpHeaders({
      Authorization: `Bearer ${this.authService.token}`,
    });

    return this.http.get<Document[]>(this.apiUrl, { headers });
  }

  getDocument(id: number): Observable<ArrayBuffer> {
    return this.http.get(`${this.apiUrl}/${id}`, {
      responseType: 'arraybuffer',
    });
  }

  // Add this method to match how your component is calling it - with a number parameter
  getDocumentById(id: number): Observable<Document> {
    return this.http.get<Document>(`${this.apiUrl}/${id}`);
  }

  getSignedDocument(id: number): Observable<ArrayBuffer> {
    return this.http.get(`${this.apiUrl}/${id}/signed`, {
      responseType: 'arraybuffer',
    });
  }

  downloadDocument(id: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/${id}/download`, {
      responseType: 'blob',
    });
  }

  signDocument(
    id: number,
    signatureData: string,
    signaturePositions: SignaturePosition[]
  ): Observable<Document> {
    // Notice this is updated to match your component which sends the whole array
    return this.http.post<Document>(`${this.apiUrl}/${id}/sign`, {
      signatureData,
      signaturePositions,
    });
  }

  deleteDocument(id: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${id}`);
  }
}

// // File: app/services/document.service.ts
// import { Injectable } from '@angular/core';
// import { HttpClient } from '@angular/common/http';
// import { Observable } from 'rxjs';
// import { Document } from '../models/document.model';
// import { SignaturePosition } from '../models/signature-position.model';
// import { environment } from '../envirennements/environnement';

// @Injectable({
//   providedIn: 'root',
// })
// export class DocumentService {
//   private uploadedFile: File | null = null;

//   setFile(file: File) {
//     this.uploadedFile = file;
//   }

//   getFile(): File | null {
//     return this.uploadedFile;
//   }
//   private apiUrl = `${environment.apiUrl}/documents`;

//   constructor(private http: HttpClient) {}

//   uploadDocument(file: File): Observable<Document> {
//     const formData = new FormData();
//     formData.append('file', file);

//     return this.http.post<Document>(`${this.apiUrl}/upload`, formData);
//   }

//   getDocuments(): Observable<Document[]> {
//     return this.http.get<Document[]>(this.apiUrl);
//   }

//   getDocument(id: number): Observable<ArrayBuffer> {
//     return this.http.get(`${this.apiUrl}/${id}`, {
//       responseType: 'arraybuffer',
//     });
//   }

//   getSignedDocument(id: number): Observable<ArrayBuffer> {
//     return this.http.get(`${this.apiUrl}/${id}/signed`, {
//       responseType: 'arraybuffer',
//     });
//   }

//   downloadDocument(id: number): Observable<Blob> {
//     return this.http.get(`${this.apiUrl}/${id}/download`, {
//       responseType: 'blob',
//     });
//   }
//   signDocument(
//     id: number,
//     signatureData: string,
//     position: SignaturePosition
//   ): Observable<Document> {
//     return this.http.post<Document>(`${this.apiUrl}/${id}/sign`, {
//       signatureData,
//       pageNum: position.pageNum,
//       x: position.x,
//       y: position.y,
//       width: position.width,
//       height: position.height,
//     });
//   }
//   deleteDocument(id: string): Observable<any> {
//     return this.http.delete(`${this.apiUrl}/${id}`);
//   }
// }

// import { Injectable } from '@angular/core';
// import { HttpClient } from '@angular/common/http';
// import { Observable } from 'rxjs';
// import { environment } from '../envirennements/environnement';
// import { Document } from '../models/document.model';

// @Injectable({
//   providedIn: 'root',
// })
// export class DocumentService {
//   private apiUrl = `${environment.apiUrl}/documents`;

//   constructor(private http: HttpClient) {}

//   // Changed parameter type to string to match component usage
//   getDocument(id: string): Observable<Document> {
//     return this.http.get<Document>(`${this.apiUrl}/${id}`);
//   }

//   getDocuments(): Observable<Document[]> {
//     return this.http.get<Document[]>(this.apiUrl);
//   }

//   uploadDocument(formData: FormData): Observable<Document> {
//     return this.http.post<Document>(this.apiUrl, formData);
//   }

//   deleteDocument(id: string): Observable<void> {
//     return this.http.delete<void>(`${this.apiUrl}/${id}`);
//   }

//   // Return type is Blob for downloadable content
//   downloadDocument(id: string): Observable<Blob> {
//     return this.http.get(`${this.apiUrl}/${id}/download`, {
//       responseType: 'blob',
//     });
//   }
// }

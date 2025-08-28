// File: app/models/document.model.ts
import { User } from './user.model';

export interface Document {
  id?: number;
  filename?: string;
  originalFile?: ArrayBuffer;
  signedFile?: ArrayBuffer;
  uploadedBy?: User;
  status?: string;
  uploadedAt?: Date;
  signedAt?: Date;
  url?: string;
}
// uploadDate: Date;
// signatureCount: number;
// fileType: string;
// fileSize: number;
// ilename, uploadDate, signatureCount, fileType, fileSize

// export interface Document {
//   id: string;
//   name: string;
//   fileType: string;
//   fileSize: number;
//   uploadDate: Date;
//   signatureCount: number;
//   status: string;
//   url?: string;
//   fileName?: string;
// }

// document.model.ts
export interface Document {
  id?: number; // Changed from string to number to match your component
  name?: string;
  filename?: string; // Added to match what's used in your component
  size?: number;
  contentType?: string;
  uploadDate?: string;
  status?: string;
  signatureCount?: number;
  lastModified?: string;
  signedUrl?: string;
  originalUrl?: string;
  thumbnailUrl?: string;
}

export enum Status {
  UPLOADED = 'UPLOADED',
  PROCESSING = 'PROCESSING',
  READY = 'READY',
  SIGNED = 'SIGNED',
  ERROR = 'ERROR',
}

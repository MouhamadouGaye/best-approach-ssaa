// File: app/models/signature.model.ts

import { User } from './user.model';

// export interface Signature {
//   id?: number;
//   user?: User;
//   signatureData?: string | number;
//   createdAt?: Date;
//   signatureDataUrl?: string;

//   // Add this:
//   date?: Date;
// }

export interface Signature {
  id?: number;
  user?: User;
  signatureData?: string | number | boolean; // raw data (maybe from backend)
  signatureDataUrl?: string; // for display
  createdAt?: Date;
  imageUrl: string;
  username: string;
  isDefault?: boolean;
}

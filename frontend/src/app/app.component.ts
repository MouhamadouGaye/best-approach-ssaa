// // // app.component.ts
// // import { Component } from '@angular/core';
// // import { RouterModule } from '@angular/router';
// // import { MatSidenavModule } from '@angular/material/sidenav'; // import what you need

// // @Component({
// //   selector: 'app-root',
// //   standalone: true,
// //   imports: [
// //     RouterModule,
// //     MatSidenavModule,
// //     // Add other Angular Material modules, common modules, and child components here
// //   ],
// //   templateUrl: './app.component.html',
// //   styleUrls: ['./app.component.scss'],
// // })
// // export class AppComponent {}

// import { Component, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
// import { RouterOutlet } from '@angular/router';
// import { CommonModule } from '@angular/common';
// import { DocumentViewerComponent } from './components/document-viewer/document-viewer.component';
// import { DocumentUploadComponent } from './components/document-upload/document-upload.component';

// @Component({
//   selector: 'app-root',
//   standalone: true,
//   imports: [RouterOutlet, CommonModule, RouterOutlet],
//   schemas: [CUSTOM_ELEMENTS_SCHEMA],
//   template: ` <router-outlet></router-outlet> `,
//   styles: [],
// })
// export class AppComponent {
//   uploadedFile: File | null = null;

//   onFileUploaded(file: File) {
//     this.uploadedFile = file;
//   }
// }

import { Component, CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { RouterOutlet } from '@angular/router'; // Import RouterOutlet for standalone component

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet], // Import RouterOutlet only here for standalone component
  schemas: [CUSTOM_ELEMENTS_SCHEMA],
  template: ` <router-outlet></router-outlet> `,
  styles: [],
})
export class AppComponent {
  uploadedFile: File | null = null;

  onFileUploaded(file: File) {
    this.uploadedFile = file;
  }
}

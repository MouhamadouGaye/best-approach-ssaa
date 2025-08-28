// register.component.ts
import { Component } from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { Router, RouterModule } from '@angular/router';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService } from '../../services/auth.service';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import {
  MatError,
  MatFormField,
  MatFormFieldModule,
  MatLabel,
} from '@angular/material/form-field';
import {
  MatProgressSpinnerModule,
  MatSpinner,
} from '@angular/material/progress-spinner';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [
    CommonModule,
    MatCardModule,
    MatFormField,
    MatError,
    MatLabel,
    ReactiveFormsModule,
    MatSpinner,
    RouterModule,
    MatInputModule,
    MatFormFieldModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSnackBarModule,
  ],
  template: `
    <div class="register-container">
      <mat-card class="register-card">
        <mat-card-header>
          <mat-card-title>Create an Account</mat-card-title>
        </mat-card-header>
        <mat-card-content>
          <form [formGroup]="registerForm" (ngSubmit)="onSubmit()">
            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Full Name</mat-label>
              <input
                matInput
                formControlName="username"
                placeholder="Enter your full name"
              />
              <mat-error
                *ngIf="registerForm.get('username')?.hasError('required')"
                >Name is required</mat-error
              >
            </mat-form-field>

            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Email</mat-label>
              <input
                matInput
                formControlName="email"
                type="email"
                placeholder="Enter your email"
              />
              <mat-error *ngIf="registerForm.get('email')?.hasError('required')"
                >Email is required</mat-error
              >
              <mat-error *ngIf="registerForm.get('email')?.hasError('email')"
                >Please enter a valid email</mat-error
              >
            </mat-form-field>

            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Password</mat-label>
              <input
                matInput
                formControlName="password"
                type="password"
                placeholder="Enter a password"
              />
              <mat-error
                *ngIf="registerForm.get('password')?.hasError('required')"
                >Password is required</mat-error
              >
              <mat-error
                *ngIf="registerForm.get('password')?.hasError('minlength')"
              >
                Password must be at least 8 characters
              </mat-error>
            </mat-form-field>

            <mat-form-field appearance="outline" class="full-width">
              <mat-label>Confirm Password</mat-label>
              <input
                matInput
                formControlName="confirmPassword"
                type="password"
                placeholder="Confirm your password"
              />
              <mat-error
                *ngIf="
                  registerForm.get('confirmPassword')?.hasError('required')
                "
              >
                Please confirm your password
              </mat-error>
              <mat-error
                *ngIf="
                  registerForm.get('confirmPassword')?.hasError('mismatch')
                "
              >
                Passwords don't match
              </mat-error>
            </mat-form-field>

            <div class="form-actions">
              <button
                mat-raised-button
                color="primary"
                type="submit"
                [disabled]="registerForm.invalid || isLoading"
              >
                <mat-spinner diameter="20" *ngIf="isLoading"></mat-spinner>
                <span *ngIf="!isLoading">Register</span>
              </button>
            </div>
          </form>
        </mat-card-content>
        <mat-card-actions>
          <a mat-button routerLink="/login">Already have an account? Log In</a>
        </mat-card-actions>
      </mat-card>
    </div>
  `,
  styles: [
    `
      .register-container {
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background-color: #f5f5f5;
      }
      .register-card {
        width: 400px;
        max-width: 90%;
      }
      .full-width {
        width: 100%;
        margin-bottom: 15px;
      }
      .form-actions {
        display: flex;
        justify-content: flex-end;
      }
      mat-spinner {
        margin-right: 8px;
        display: inline-block;
      }
    `,
  ],
})
export class RegisterComponent {
  registerForm: FormGroup;
  isLoading = false;

  constructor(
    private fb: FormBuilder,
    private authService: AuthService,
    private router: Router,
    private snackBar: MatSnackBar
  ) {
    this.registerForm = this.fb.group(
      {
        username: ['', [Validators.required]],
        email: ['', [Validators.required, Validators.email]],
        password: ['', [Validators.required, Validators.minLength(8)]],
        confirmPassword: ['', [Validators.required]],
      },
      { validators: this.checkPasswords }
    );
  }

  checkPasswords(group: FormGroup) {
    const password = group.get('password')?.value;
    const confirmPassword = group.get('confirmPassword')?.value;
    return password === confirmPassword ? null : { mismatch: true };
  }

  onSubmit(): void {
    if (this.registerForm.valid) {
      this.isLoading = true;

      // // Create payload with correct field names
      // const payload = {
      //   username: this.registerForm.get('username')?.value,
      //   email: this.registerForm.get('email')?.value,
      //   password: this.registerForm.get('password')?.value,
      // }; this also works as the 2 lines below

      const { username, email, password } = this.registerForm.value;
      const payload = { username, email, password };

      console.log('Final payload before sending:', payload);

      this.authService.register(payload).subscribe({
        next: () => {
          this.isLoading = false;
          this.snackBar.open(
            'Registration successful! Please log in.',
            'Close',
            {
              duration: 5000,
              panelClass: ['success-snackbar'],
            }
          );
          this.router.navigate(['/login']);
        },
        error: (error) => {
          this.isLoading = false;
          this.snackBar.open(
            error.error?.message || 'Registration failed',
            'Close',
            {
              duration: 5000,
              panelClass: ['error-snackbar'],
            }
          );
        },
      });
    }
  }
}

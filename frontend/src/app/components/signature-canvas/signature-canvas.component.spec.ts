import { ComponentFixture, TestBed } from '@angular/core/testing';

import { SignatureCanvasComponent } from './signature-canvas.component';

describe('SignatureCanvasComponent', () => {
  let component: SignatureCanvasComponent;
  let fixture: ComponentFixture<SignatureCanvasComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [SignatureCanvasComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(SignatureCanvasComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

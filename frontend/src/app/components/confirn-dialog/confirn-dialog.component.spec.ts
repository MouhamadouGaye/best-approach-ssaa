import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ConfirnDialogComponent } from './confirn-dialog.component';

describe('ConfirnDialogComponent', () => {
  let component: ConfirnDialogComponent;
  let fixture: ComponentFixture<ConfirnDialogComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [ConfirnDialogComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(ConfirnDialogComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

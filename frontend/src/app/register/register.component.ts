/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { SecurityAnswerService } from '../Services/security-answer.service'
import { UserService } from '../Services/user.service'
import { type AbstractControl, UntypedFormControl, Validators, FormsModule, ReactiveFormsModule } from '@angular/forms'
import { Component, NgZone, type OnInit } from '@angular/core'
import { SecurityQuestionService } from '../Services/security-question.service'
import { Router, RouterLink } from '@angular/router'
import { library } from '@fortawesome/fontawesome-svg-core'
import { MatSnackBar } from '@angular/material/snack-bar'
import { HttpClient } from '@angular/common/http'

import { faExclamationCircle, faUserPlus } from '@fortawesome/free-solid-svg-icons'
import { FormSubmitService } from '../Services/form-submit.service'
import { SnackBarHelperService } from '../Services/snack-bar-helper.service'
import { TranslateService, TranslateModule } from '@ngx-translate/core'
import { type SecurityQuestion } from '../Models/securityQuestion.model'
import { MatButtonModule } from '@angular/material/button'
import { MatOption } from '@angular/material/core'
import { MatSelect } from '@angular/material/select'
import { PasswordStrengthComponent } from '../password-strength/password-strength.component'
import { PasswordStrengthInfoComponent } from '../password-strength-info/password-strength-info.component'
import { MatSlideToggle } from '@angular/material/slide-toggle'
import { CommonModule } from '@angular/common'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule, MatLabel, MatError, MatHint } from '@angular/material/form-field'
import { MatCardModule } from '@angular/material/card'

import { MatIconModule } from '@angular/material/icon'

library.add(faUserPlus, faExclamationCircle)

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss'],
  imports: [CommonModule,MatCardModule, TranslateModule, MatFormFieldModule, MatLabel, MatInputModule, FormsModule, ReactiveFormsModule, MatError, MatHint, MatSlideToggle, PasswordStrengthComponent, PasswordStrengthInfoComponent, MatSelect, MatOption, MatButtonModule, RouterLink, MatIconModule]
})
export class RegisterComponent implements OnInit {
  public emailControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.email])
  public passwordControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, Validators.minLength(5), Validators.maxLength(40)])
  public repeatPasswordControl: UntypedFormControl = new UntypedFormControl('', [Validators.required, matchValidator(this.passwordControl)])
  public securityQuestionControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public securityAnswerControl: UntypedFormControl = new UntypedFormControl('', [Validators.required])
  public securityQuestions!: SecurityQuestion[]
  public selected?: number
  public error: string | null = null
public passwordStrength: string | null = null
public isCheckingStrength = false

  constructor (private readonly securityQuestionService: SecurityQuestionService,
    private readonly userService: UserService,
    private readonly securityAnswerService: SecurityAnswerService,
    private readonly router: Router,
    private readonly formSubmitService: FormSubmitService,
    private readonly translateService: TranslateService,
    private readonly snackBar: MatSnackBar,
    private readonly snackBarHelperService: SnackBarHelperService,
    private readonly ngZone: NgZone,
   private readonly http: HttpClient) { }

  ngOnInit (): void {
    this.securityQuestionService.find(null).subscribe({
      next: (securityQuestions: any) => {
        this.securityQuestions = securityQuestions
      },
      error: (err) => { console.log(err) }
    })

    this.formSubmitService.attachEnterKeyHandler('registration-form', 'registerButton', () => { this.save() })
  }
 /* checkPasswordStrength (): void {
  const password = this.passwordControl.value
  if (!password) {
    this.passwordStrength = null
    return
  }

  this.isCheckingStrength = true
  this.http.post<any>('/rest/ml-password-strength', { password }).subscribe({
    next: (res) => {console.log('Réponse du serveur ML:', res); // ✅ affiche la réponse dans la console navigateur
     
      this.passwordStrength = res.strength || res.strengths?.[0] || 'inconnue'
      this.isCheckingStrength = false
    },
    error: (err) => {
      console.error('Erreur lors de la vérification ML:', err)
      this.passwordStrength = 'erreur'
      this.isCheckingStrength = false
    }
  })
}*/
checkPasswordStrength(): void {
  const password = this.passwordControl.value;
  if (!password) {
    this.passwordStrength = null;
    return;
  }

  this.isCheckingStrength = true;

  this.http.post<any>('/rest/ml-password-strength', { password }).subscribe({
    next: (res) => {
      
      //  Force Angular à rafraîchir la vue
      this.ngZone.run(() => {
        this.passwordStrength =
          res.strengths?.[0] ||
          res.strength ||
          res.label?.[0] ||
          'inconnue';
        this.isCheckingStrength = false;
      });
    },
    error: (err) => {
      console.error(' Erreur ML:', err);
      this.ngZone.run(() => {
        this.passwordStrength = 'erreur';
        this.isCheckingStrength = false;
      });
    }
  });
}


getColor(strength: string): string {
  switch (strength) {
    case 'très_faible':
    case 'faible':
      return 'warn'   // rouge
    case 'moyen':
      return 'accent' // orange
    case 'fort':
      return 'primary' // vert/bleu
    default:
      return 'primary'
  }
}


  save () {
    const user = {
      email: this.emailControl.value,
      password: this.passwordControl.value,
      passwordRepeat: this.repeatPasswordControl.value,
      securityQuestion: this.securityQuestions.find((question) => question.id === this.securityQuestionControl.value),
      securityAnswer: this.securityAnswerControl.value
    }

    this.userService.save(user).subscribe({
      next: (response: any) => {
        this.securityAnswerService.save({
          UserId: response.id,
          answer: this.securityAnswerControl.value,
          SecurityQuestionId: this.securityQuestionControl.value
        }).subscribe(() => {
          this.ngZone.run(async () => await this.router.navigate(['/login']))
          this.snackBarHelperService.open('CONFIRM_REGISTER')
        })
      },
      error: (err) => {
        console.log(err)
        if (err.error?.errors) {
          const error = err.error.errors[0]
          if (error.message) {
          // eslint-disable-next-line @typescript-eslint/restrict-plus-operands
            this.error = error.message[0].toUpperCase() + error.message.slice(1)
          } else {
            this.error = error
          }
        }
      }
    })
  }
}

function matchValidator (passwordControl: AbstractControl) {
  return function matchOtherValidate (repeatPasswordControl: UntypedFormControl) {
    const password = passwordControl.value
    const passwordRepeat = repeatPasswordControl.value
    if (password !== passwordRepeat) {
      return { notSame: true }
    }
    return null
  }
}

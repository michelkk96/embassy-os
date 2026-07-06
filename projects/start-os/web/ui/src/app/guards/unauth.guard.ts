import { inject, Injectable } from '@angular/core'
import { Router, UrlTree } from '@angular/router'
import { map, Observable } from 'rxjs'
import { AuthService } from '../services/auth.service'

@Injectable({
  providedIn: 'root',
})
export class UnauthGuard {
  private readonly authService = inject(AuthService)
  private readonly router = inject(Router)

  canActivate(): Observable<boolean | UrlTree> {
    return this.authService.isVerified$.pipe(
      map(verified => !verified || this.router.parseUrl('')),
    )
  }
}

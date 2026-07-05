import { inject, Injectable, NgZone } from '@angular/core'
import { Router } from '@angular/router'
import { distinctUntilChanged, map, ReplaySubject } from 'rxjs'
import { StorageService } from './storage.service'

export enum AuthState {
  UNVERIFIED,
  VERIFIED,
}
@Injectable({
  providedIn: 'root',
})
export class AuthService {
  private readonly storage = inject(StorageService)
  private readonly zone = inject(NgZone)
  private readonly router = inject(Router)
  private readonly LOGGED_IN_KEY = 'loggedIn'
  private readonly authState$ = new ReplaySubject<AuthState>(1)

  readonly isVerified$ = this.authState$.pipe(
    map(state => state === AuthState.VERIFIED),
    distinctUntilChanged(),
  )

  init(): void {
    if (this.storage.get(this.LOGGED_IN_KEY)) {
      this.setVerified()
    } else {
      this.setUnverified(true)
    }
  }

  setVerified(): void {
    this.storage.set(this.LOGGED_IN_KEY, true)
    this.authState$.next(AuthState.VERIFIED)
  }

  setUnverified(skipNavigation = false): void {
    this.authState$.next(AuthState.UNVERIFIED)
    this.storage.clear()

    if (!skipNavigation) {
      this.zone.run(() => {
        this.router.navigate(['/login'], { replaceUrl: true })
      })
    }
  }
}

import { inject, Injectable } from '@angular/core'
import { PatchDB } from 'patch-db-client'
import { Observable, tap } from 'rxjs'
import { AuthService } from 'src/app/services/auth.service'
import { DataModel } from './patch-db/data-model'

// Start and stop PatchDb upon verification
@Injectable({
  providedIn: 'root',
})
export class PatchMonitorService extends Observable<unknown> {
  private readonly patch = inject<PatchDB<DataModel>>(PatchDB)
  private readonly stream$ = inject(AuthService).isVerified$.pipe(
    tap(verified => (verified ? this.patch.start() : this.patch.stop())),
  )

  constructor() {
    super(subscriber => this.stream$.subscribe(subscriber))
  }
}

import { computed, inject, Signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { PatchDB } from 'patch-db-client'
import { of } from 'rxjs'
import {
  DataModel,
  PackageDataEntry,
} from 'src/app/services/patch-db/data-model'
import { renderPkgStatus } from 'src/app/services/pkg-status-rendering.service'

// The service-status gate shared by the Address Requirements modals.
//
// A non-SSL binding is served directly by the service, so its port-forward and
// firewall probes only mean anything while the service is running. An SSL
// binding is fronted by the always-up OS reverse proxy, so it stays testable
// regardless — its status is never watched, which also keeps the common (HTTP)
// case off patch-db entirely.
//
// Gating on `primary` rather than the base status is deliberate: a failing or
// starting health check can equally stop the service serving, so the stricter
// reading is the safer one to disable a test on.
export function injectTestStatus(
  packageId: string,
  addSsl: boolean,
): {
  pkg: Signal<PackageDataEntry | undefined>
  testDisabled: Signal<boolean>
} {
  const patch = inject<PatchDB<DataModel>>(PatchDB)
  const pkg = toSignal(
    !addSsl && packageId
      ? patch.watch$('packageData', packageId)
      : of(undefined),
  )

  return {
    pkg,
    // Nothing watched (an SSL binding, or an interface with no service of its
    // own) means nothing to gate on, so the tests stay enabled.
    testDisabled: computed(() => {
      const p = pkg()
      return !!p && renderPkgStatus(p).primary !== 'running'
    }),
  }
}

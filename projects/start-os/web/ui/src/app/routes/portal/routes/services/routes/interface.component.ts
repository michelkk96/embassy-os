import { UpperCasePipe } from '@angular/common'
import { Component, computed, inject } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute, RouterLink } from '@angular/router'
import { getPkgId, i18nPipe } from '@start9labs/shared'
import { TuiButton, TuiTitle } from '@taiga-ui/core'
import { TuiBadge } from '@taiga-ui/kit'
import { TuiHeader } from '@taiga-ui/layout'
import { PatchDB } from 'patch-db-client'
import { InterfaceComponent } from 'src/app/routes/portal/components/interfaces/interface.component'
import {
  getInterfaceBadgeAppearance,
  InterfaceService,
} from 'src/app/routes/portal/components/interfaces/interface.service'
import { GatewayService } from 'src/app/services/gateway.service'
import { DataModel } from 'src/app/services/patch-db/data-model'
import { getInstalledBaseStatus } from 'src/app/services/pkg-status-rendering.service'
import { TitleDirective } from 'src/app/services/title.service'

@Component({
  template: `
    @if (iface(); as iface) {
      <!-- Desktop: an in-page header (the *title bar is mobile-only). -->
      <header tuiHeader class="inline">
        <a
          tuiIconButton
          appearance="flat-grayscale"
          iconStart="@tui.arrow-left"
          routerLink=".."
        >
          {{ 'Back' | i18n }}
        </a>
        <hgroup tuiTitle>
          <h3>
            {{ iface.name }}
            <span tuiBadge [appearance]="getAppearance(iface.type)">
              {{ iface.type | uppercase }}
            </span>
            @if (iface.portRange) {
              <span tuiBadge appearance="neutral">{{ iface.portRange }}</span>
            }
          </h3>
        </hgroup>
      </header>

      <!-- Mobile: override the app title bar (hides the service title). -->
      <div *title class="title">
        <a routerLink=".." tuiIconButton iconStart="@tui.arrow-left">
          {{ 'Back' | i18n }}
        </a>
        <b>{{ iface.name }}</b>
        <span tuiBadge [appearance]="getAppearance(iface.type)">
          {{ iface.type | uppercase }}
        </span>
        @if (iface.portRange) {
          <span tuiBadge appearance="neutral">{{ iface.portRange }}</span>
        }
      </div>

      <service-interface
        [packageId]="pkgId"
        [value]="iface"
        [isRunning]="isRunning()"
      />
    }
  `,
  styles: `
    .inline {
      margin-bottom: 1rem;
    }

    .title {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-inline-start: -1rem;
    }

    :host-context(tui-root._mobile) .inline {
      display: none;
    }

    .inline [tuiBadge] {
      margin-inline-start: 0.25rem;
    }
  `,
  host: { class: 'g-subpage' },
  providers: [GatewayService],
  imports: [
    RouterLink,
    TitleDirective,
    TuiButton,
    TuiBadge,
    TuiHeader,
    TuiTitle,
    InterfaceComponent,
    i18nPipe,
    UpperCasePipe,
  ],
})
export default class ServiceInterfaceRoute {
  private readonly interfaceService = inject(InterfaceService)
  private readonly gatewayService = inject(GatewayService)
  private readonly patch = inject<PatchDB<DataModel>>(PatchDB)

  readonly pkgId = getPkgId()
  private readonly interfaceId =
    inject(ActivatedRoute).snapshot.paramMap.get('interfaceId') || ''

  readonly pkg = toSignal(this.patch.watch$('packageData', this.pkgId))
  private readonly allPackageData = toSignal(this.patch.watch$('packageData'))

  readonly isRunning = computed((pkg = this.pkg()) =>
    pkg ? getInstalledBaseStatus(pkg.statusInfo) === 'running' : false,
  )

  readonly iface = computed(() => {
    const pkg = this.pkg()
    return pkg
      ? this.interfaceService
          .getServiceInterfaces(
            pkg,
            this.gatewayService.gateways() || [],
            this.allPackageData(),
          )
          .find(i => i.id === this.interfaceId)
      : undefined
  })

  protected readonly getAppearance = getInterfaceBadgeAppearance
}

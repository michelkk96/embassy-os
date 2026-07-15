import { UpperCasePipe } from '@angular/common'
import { Component, computed, inject } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { RouterLink } from '@angular/router'
import { getPkgId, i18nPipe } from '@start9labs/shared'
import { TuiCell, TuiIcon, TuiTitle } from '@taiga-ui/core'
import { TuiBadge } from '@taiga-ui/kit'
import { PatchDB } from 'patch-db-client'
import { PlaceholderComponent } from 'src/app/routes/portal/components/placeholder.component'
import {
  getInterfaceBadgeAppearance,
  InterfaceService,
} from 'src/app/routes/portal/components/interfaces/interface.service'
import { GatewayService } from 'src/app/services/gateway.service'
import { DataModel } from 'src/app/services/patch-db/data-model'

@Component({
  template: `
    @if (pkg()) {
      @if (interfaces().length) {
        @for (iface of interfaces(); track iface.id) {
          <a tuiCell [routerLink]="iface.id">
            <span tuiTitle>
              <b>
                {{ iface.name }}
                <span tuiBadge [appearance]="getAppearance(iface.type)">
                  {{ iface.type | uppercase }}
                </span>
                @if (iface.portRange) {
                  <span tuiBadge appearance="neutral">
                    {{ iface.portRange }}
                  </span>
                }
              </b>
              @if (iface.description) {
                <span tuiSubtitle>{{ iface.description }}</span>
              }
            </span>
            <tui-icon icon="@tui.chevron-right" />
          </a>
        }
      } @else {
        <app-placeholder icon="@tui.monitor-x">
          {{ 'No service interfaces' | i18n }}
        </app-placeholder>
      }
    }
  `,
  styles: `
    [tuiCell] {
      border-radius: 0;
      box-shadow: inset 0 -1px var(--tui-background-neutral-1);
    }

    [tuiCell]:last-child {
      box-shadow: none;
    }

    [tuiBadge] {
      margin-inline-start: 0.25rem;
    }
  `,
  host: { class: 'g-subpage' },
  providers: [GatewayService],
  imports: [
    RouterLink,
    TuiCell,
    TuiIcon,
    TuiTitle,
    TuiBadge,
    PlaceholderComponent,
    i18nPipe,
    UpperCasePipe,
  ],
})
export default class ServiceInterfacesRoute {
  private readonly interfaceService = inject(InterfaceService)
  private readonly gatewayService = inject(GatewayService)
  private readonly patch = inject<PatchDB<DataModel>>(PatchDB)

  readonly pkg = toSignal(this.patch.watch$('packageData', getPkgId()))
  private readonly allPackageData = toSignal(this.patch.watch$('packageData'))

  readonly interfaces = computed(() => {
    const pkg = this.pkg()
    return pkg
      ? this.interfaceService.getServiceInterfaces(
          pkg,
          this.gatewayService.gateways() || [],
          this.allPackageData(),
        )
      : []
  })

  protected readonly getAppearance = getInterfaceBadgeAppearance
}

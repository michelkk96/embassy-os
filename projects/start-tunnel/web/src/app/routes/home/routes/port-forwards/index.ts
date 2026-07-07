import { Component, computed, inject, signal, Signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { FormsModule } from '@angular/forms'
import { ErrorService, TaskService } from '@start9labs/shared'
import { T, utils } from '@start9labs/start-core'
import { TuiResponsiveDialogService } from '@taiga-ui/addon-mobile'
import {
  TuiButton,
  TuiDataList,
  TuiDropdown,
  TuiIcon,
  TuiLoader,
  TuiTextfield,
  TuiTitle,
} from '@taiga-ui/core'
import {
  TUI_CONFIRM,
  TuiNotificationMiddleService,
  TuiSkeleton,
  TuiSwitch,
} from '@taiga-ui/kit'
import { TuiCardLarge, TuiHeader } from '@taiga-ui/layout'
import { PatchDB } from 'patch-db-client'
import { filter, map } from 'rxjs'
import { PlaceholderComponent } from 'src/app/routes/home/components/placeholder'
import { PORT_FORWARDS_ADD } from 'src/app/routes/home/routes/port-forwards/add'
import { PORT_FORWARDS_EDIT_LABEL } from 'src/app/routes/home/routes/port-forwards/edit-label'
import { deviceIpv6 } from 'src/app/routes/home/routes/devices/utils'
import { ApiService } from 'src/app/services/api/api.service'
import { TunnelData } from 'src/app/services/patch-db/data-model'

import { mapForwards, mapPinholes, MappedDevice, MappedForward } from './utils'

@Component({
  template: `
    <div tuiCardLarge="compact" appearance="floating">
      <header tuiHeader="body-l">
        <tui-icon icon="@tui.pencil" />
        <h3 tuiTitle>Manual</h3>
        <aside tuiAccessories>
          <button tuiButton iconStart="@tui.plus" (click)="onAdd()">Add</button>
        </aside>
      </header>
      <table class="g-table" [tuiSkeleton]="!portForwards()">
        <thead>
          <tr>
            <th></th>
            <th>Label</th>
            <th>External IP</th>
            <th>External Port</th>
            <th>Hostname</th>
            <th>Server</th>
            <th>Internal Port</th>
            <th>Protocol</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          @for (forward of manual(); track $index) {
            <tr>
              <td>
                <tui-loader
                  size="xs"
                  [loading]="toggling() === key(forward)"
                  [overlay]="true"
                >
                  <input
                    tuiSwitch
                    type="checkbox"
                    size="s"
                    [style.display]="'flex'"
                    [showIcons]="false"
                    [ngModel]="forward.enabled"
                    (ngModelChange)="onToggle(forward)"
                  />
                </tui-loader>
              </td>
              <td>{{ forward.label || '—' }}</td>
              <td>{{ forward.externalip }}</td>
              <td>{{ span(forward.externalport, forward.count) }}</td>
              <td>{{ forward.sni || '—' }}</td>
              <td>{{ forward.device.name }}</td>
              <td>{{ span(forward.internalport, forward.count) }}</td>
              <td>TCP/UDP</td>
              <td [style.padding-inline-end.rem]="0.625">
                <button
                  tuiIconButton
                  size="xs"
                  tuiDropdown
                  tuiDropdownAuto
                  appearance="flat-grayscale"
                  iconStart="@tui.ellipsis-vertical"
                >
                  Actions
                  <tui-data-list
                    *tuiDropdown="let close"
                    size="s"
                    (click)="close()"
                  >
                    <button
                      tuiOption
                      iconStart="@tui.pencil"
                      (click)="onEditLabel(forward)"
                    >
                      {{ forward.label ? 'Rename' : 'Add label' }}
                    </button>
                    <button
                      tuiOption
                      iconStart="@tui.trash"
                      (click)="onDelete(forward)"
                    >
                      Delete
                    </button>
                  </tui-data-list>
                </button>
              </td>
            </tr>
          } @empty {
            <tr>
              <td colspan="9">
                <app-placeholder icon="@tui.globe">
                  No port forwards
                </app-placeholder>
              </td>
            </tr>
          }
        </tbody>
      </table>
    </div>

    <div tuiCardLarge="compact" appearance="floating">
      <header tuiHeader="body-l">
        <tui-icon icon="@tui.zap" />
        <h3 tuiTitle>Automatic</h3>
      </header>
      <table class="g-table no-actions" [tuiSkeleton]="!portForwards()">
        <thead>
          <tr>
            <th>External IP</th>
            <th>External Port</th>
            <th>Hostname</th>
            <th>Server</th>
            <th>Internal Port</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          @for (forward of automatic(); track $index) {
            <tr>
              <td>{{ forward.externalip }}</td>
              <td>{{ span(forward.externalport, forward.count) }}</td>
              <td>{{ forward.sni || '—' }}</td>
              <td>{{ forward.device.name }}</td>
              <td>{{ span(forward.internalport, forward.count) }}</td>
              <td>TCP/UDP</td>
            </tr>
          } @empty {
            <tr>
              <td colspan="6">
                <app-placeholder icon="@tui.globe">
                  No port forwards
                </app-placeholder>
              </td>
            </tr>
          }
        </tbody>
      </table>
    </div>

    <div tuiCardLarge="compact" appearance="floating">
      <header tuiHeader="body-l">
        <tui-icon icon="@tui.milestone" />
        <h3 tuiTitle>
          HTTP Redirects
          <span tuiSubtitle>
            Plain http:// requests to port 80 of these public IPs are redirected
            to https://. Turned off automatically while a port forward occupies
            port 80.
          </span>
        </h3>
      </header>
      <table class="g-table no-actions" [tuiSkeleton]="!httpRedirects()">
        <thead>
          <tr>
            <th></th>
            <th>External IP</th>
            <th>External Port</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          @for (redirect of redirects(); track redirect.ip) {
            <tr>
              <td>
                <tui-loader
                  size="xs"
                  [loading]="togglingRedirect() === redirect.ip"
                  [overlay]="true"
                >
                  <input
                    tuiSwitch
                    type="checkbox"
                    size="s"
                    [style.display]="'flex'"
                    [showIcons]="false"
                    [disabled]="redirect.forwarded"
                    [ngModel]="redirect.enabled && !redirect.forwarded"
                    (ngModelChange)="onToggleRedirect(redirect)"
                  />
                </tui-loader>
              </td>
              <td>{{ redirect.ip }}</td>
              <td>80</td>
              <td>
                {{
                  redirect.forwarded
                    ? 'Port 80 forwarded'
                    : redirect.enabled
                      ? 'Redirecting → HTTPS'
                      : 'Off'
                }}
              </td>
            </tr>
          } @empty {
            <tr>
              <td colspan="4">
                <app-placeholder icon="@tui.globe">
                  No public IPv4 addresses
                </app-placeholder>
              </td>
            </tr>
          }
        </tbody>
      </table>
    </div>
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
  `,
  imports: [
    FormsModule,
    TuiButton,
    TuiCardLarge,
    TuiDropdown,
    TuiDataList,
    TuiLoader,
    TuiSwitch,
    TuiTextfield,
    PlaceholderComponent,
    TuiSkeleton,
    TuiHeader,
    TuiIcon,
    TuiTitle,
  ],
})
export default class PortForwards {
  private readonly dialogs = inject(TuiResponsiveDialogService)
  private readonly api = inject(ApiService)
  private readonly tasks = inject(TaskService)
  private readonly patch = inject<PatchDB<TunnelData>>(PatchDB)
  private readonly errorService = inject(ErrorService)
  private readonly ips = toSignal(
    this.patch.watch$('gateways').pipe(
      map(g =>
        Object.values(g)
          .flatMap(
            val => val.ipInfo?.subnets.map(s => utils.IpNet.parse(s)) || [],
          )
          .filter(s => s.isIpv4() && s.isPublic())
          .map(s => s.address),
      ),
    ),
    { initialValue: [] },
  )

  // Only servers can receive forwards, so the picker lists servers only. Each
  // carries its computed IPv6 GUA (null when the subnet has no v6 prefix).
  private readonly devices: Signal<MappedDevice[]> = toSignal(
    this.patch.watch$('wg', 'subnets').pipe(
      map(subnets =>
        Object.values(subnets).flatMap(subnet =>
          Object.entries(subnet.clients)
            .filter(([, c]) => c.kind === 'server')
            .map(([ip, { name }]) => ({
              ip,
              name,
              ipv6: deviceIpv6(subnet.ipv6, ip),
            })),
        ),
      ),
    ),
    { initialValue: [] },
  )

  // All devices (any kind), so rows targeting a client still resolve a name.
  private readonly allDevices: Signal<MappedDevice[]> = toSignal(
    this.patch.watch$('wg', 'subnets').pipe(
      map(subnets =>
        Object.values(subnets).flatMap(subnet =>
          Object.entries(subnet.clients).map(([ip, { name }]) => ({
            ip,
            name,
            ipv6: deviceIpv6(subnet.ipv6, ip),
          })),
        ),
      ),
    ),
    { initialValue: [] },
  )

  protected readonly portForwards = toSignal(this.patch.watch$('portForwards'))
  protected readonly pinholes = toSignal(this.patch.watch$('pinholes6'))
  protected readonly httpRedirects = toSignal(
    this.patch.watch$('httpRedirects'),
  )
  protected readonly redirects = computed<MappedRedirect[]>(() => {
    const disabled = new Set(this.httpRedirects()?.disabled || [])
    const forwards = this.portForwards() || {}
    return this.ips().map(ip => ({
      ip,
      enabled: !disabled.has(ip),
      forwarded: portEightyForwarded(forwards, ip),
    }))
  })
  protected readonly forwards = computed(() => [
    ...mapForwards(this.portForwards() || {}, this.allDevices()),
    ...mapPinholes(this.pinholes() || {}, this.allDevices()),
  ])
  protected readonly manual = computed(() =>
    this.forwards().filter(f => !f.auto),
  )
  protected readonly automatic = computed(() =>
    this.forwards().filter(f => f.auto),
  )

  protected readonly toggling = signal<string | null>(null)
  protected readonly togglingRedirect = signal<string | null>(null)

  protected key(forward: MappedForward): string {
    return `${forward.ipVersion}:${forward.externalip}:${forward.externalport}:${forward.hostname ?? ''}`
  }

  // Renders a forwarded port span: a single port when count is 1, else `start-end`.
  protected span(startPort: string, count: number): string {
    const start = Number(startPort)
    return count > 1 ? `${start}-${start + count - 1}` : startPort
  }

  protected async onToggle(forward: MappedForward) {
    this.toggling.set(this.key(forward))

    try {
      if (forward.ipVersion === 'ipv6') {
        await this.api.setPinholeEnabled({
          gua: forward.externalip,
          externalPort: Number(forward.externalport),
          enabled: !forward.enabled,
        })
      } else {
        await this.api.setForwardEnabled({
          source: `${forward.externalip}:${forward.externalport}`,
          enabled: !forward.enabled,
          hostname: forward.hostname,
        })
      }
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.toggling.set(null)
    }
  }

  protected async onToggleRedirect(redirect: MappedRedirect) {
    if (redirect.forwarded) return

    this.togglingRedirect.set(redirect.ip)

    try {
      await this.api.setHttpRedirectEnabled({
        ip: redirect.ip,
        enabled: !redirect.enabled,
      })
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.togglingRedirect.set(null)
    }
  }

  protected onAdd(): void {
    this.dialogs
      .open(PORT_FORWARDS_ADD, {
        label: 'Add port forward',
        data: { ips: this.ips, devices: this.devices },
      })
      .subscribe()
  }

  protected onEditLabel(forward: MappedForward): void {
    this.dialogs
      .open(PORT_FORWARDS_EDIT_LABEL, {
        label: 'Edit label',
        data: {
          source: `${forward.externalip}:${forward.externalport}`,
          label: forward.label,
          hostname: forward.hostname,
          pinhole:
            forward.ipVersion === 'ipv6'
              ? {
                  gua: forward.externalip,
                  externalPort: Number(forward.externalport),
                }
              : undefined,
        },
      })
      .subscribe()
  }

  protected onDelete(forward: MappedForward): void {
    this.dialogs
      .open(TUI_CONFIRM, { label: 'Are you sure?' })
      .pipe(filter(Boolean))
      .subscribe(() =>
        this.tasks.run(async () => {
          if (forward.ipVersion === 'ipv6') {
            await this.api.deletePinhole({
              gua: forward.externalip,
              externalPort: Number(forward.externalport),
            })
          } else {
            await this.api.deleteForward({
              source: `${forward.externalip}:${forward.externalport}`,
              hostname: forward.hostname,
            })
          }
        }),
      )
  }
}

interface MappedRedirect {
  ip: string
  enabled: boolean
  forwarded: boolean
}

// Whether any forward on `ip` covers port 80 (a DNAT range or an SNI/single
// entry), in which case the redirect yields and its checkbox is disabled.
function portEightyForwarded(
  forwards: Record<string, T.Tunnel.PortForward>,
  ip: string,
): boolean {
  return Object.entries(forwards).some(([source, pf]) => {
    const idx = source.lastIndexOf(':')
    if (idx < 0 || source.slice(0, idx) !== ip) return false
    const start = Number(source.slice(idx + 1))
    const span = pf.kind === 'dnat' ? (pf.count ?? 1) : 1
    return start <= 80 && 80 <= start + span - 1
  })
}

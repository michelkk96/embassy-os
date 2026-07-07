import { Component, computed, inject, signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { FormsModule } from '@angular/forms'
import { Router } from '@angular/router'
import { ErrorService, TaskService } from '@start9labs/shared'
import { T, utils } from '@start9labs/start-core'
import { TuiResponsiveDialogService } from '@taiga-ui/addon-mobile'
import {
  TuiButton,
  TuiCell,
  TuiIcon,
  TuiLoader,
  TuiTitle,
} from '@taiga-ui/core'
import { TuiBadge, TuiButtonLoading, TuiSwitch } from '@taiga-ui/kit'
import { TuiCardLarge, TuiHeader } from '@taiga-ui/layout'
import { PatchDB } from 'patch-db-client'
import { map } from 'rxjs'
import { ApiService } from 'src/app/services/api/api.service'
import { AuthService } from 'src/app/services/auth.service'
import { TunnelData } from 'src/app/services/patch-db/data-model'
import { UpdateService } from 'src/app/services/update.service'
import { CHANGE_PASSWORD } from './change-password'

@Component({
  template: `
    <div tuiCardLarge="compact" appearance="floating">
      <div tuiCell>
        <span tuiTitle>
          <strong>
            Version
            @if (update.hasUpdate()) {
              <span tuiBadge appearance="positive" size="s">
                Update Available
              </span>
            }
          </strong>
          <span tuiSubtitle>Current: {{ update.installed() ?? '—' }}</span>
        </span>
        @if (update.hasUpdate()) {
          <button tuiButton size="s" [loading]="applying()" (click)="onApply()">
            Update to {{ update.candidate() }}
          </button>
        } @else {
          <button
            tuiButton
            size="s"
            appearance="secondary"
            [loading]="checking()"
            (click)="onCheckUpdate()"
          >
            Check for updates
          </button>
        }
      </div>
    </div>
    <div tuiCardLarge="compact" appearance="floating">
      <header tuiHeader="body-l">
        <tui-icon icon="@tui.milestone" />
        <h3 tuiTitle>HTTP Redirect (80 → 443)</h3>
      </header>
      <table class="g-table no-actions">
        <thead>
          <tr>
            <th>WAN IP</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          @for (redirect of redirects(); track redirect.ip) {
            <tr>
              <td>{{ redirect.ip }}</td>
              <td>
                <tui-loader
                  size="xs"
                  [loading]="toggling() === redirect.ip"
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
            </tr>
          } @empty {
            <tr>
              <td colspan="2">No public IPv4 addresses</td>
            </tr>
          }
        </tbody>
      </table>
    </div>
    <div
      tuiCardLarge="compact"
      appearance="floating"
      [style.align-items]="'start'"
    >
      <button tuiButton size="s" (click)="onChangePassword()">
        Change password
      </button>
      <button
        tuiButton
        size="s"
        iconStart="@tui.rotate-cw"
        [loading]="restarting()"
        (click)="onRestart()"
      >
        Reboot VPS
      </button>
      <button tuiButton size="s" iconStart="@tui.log-out" (click)="onLogout()">
        Logout
      </button>
    </div>
  `,
  styles: `
    :host {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      max-inline-size: 50rem;
    }
  `,
  imports: [
    FormsModule,
    TuiCardLarge,
    TuiCell,
    TuiTitle,
    TuiHeader,
    TuiIcon,
    TuiButton,
    TuiButtonLoading,
    TuiBadge,
    TuiLoader,
    TuiSwitch,
  ],
})
export default class Settings {
  private readonly dialogs = inject(TuiResponsiveDialogService)
  private readonly errorService = inject(ErrorService)
  private readonly api = inject(ApiService)
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)
  private readonly tasks = inject(TaskService)
  private readonly patch = inject<PatchDB<TunnelData>>(PatchDB)

  protected readonly update = inject(UpdateService)
  protected readonly checking = signal(false)
  protected readonly applying = signal(false)
  protected readonly restarting = signal(false)
  protected readonly toggling = signal<string | null>(null)

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
  private readonly httpRedirects = toSignal(this.patch.watch$('httpRedirects'))
  private readonly portForwards = toSignal(this.patch.watch$('portForwards'))
  protected readonly redirects = computed(() => {
    const disabled = new Set(this.httpRedirects()?.disabled || [])
    const forwards = this.portForwards() || {}
    return this.ips().map(ip => ({
      ip,
      enabled: !disabled.has(ip),
      forwarded: portEightyForwarded(forwards, ip),
    }))
  })

  protected async onToggleRedirect(redirect: {
    ip: string
    enabled: boolean
    forwarded: boolean
  }) {
    if (redirect.forwarded) return

    this.toggling.set(redirect.ip)

    try {
      await this.api.setHttpRedirectEnabled({
        ip: redirect.ip,
        enabled: !redirect.enabled,
      })
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.toggling.set(null)
    }
  }

  protected onChangePassword(): void {
    this.dialogs.open(CHANGE_PASSWORD, { label: 'Change Password' }).subscribe()
  }

  protected async onCheckUpdate() {
    this.checking.set(true)

    try {
      await this.update.checkUpdate()
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.checking.set(false)
    }
  }

  protected async onApply() {
    this.applying.set(true)

    try {
      await this.update.applyUpdate()
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.applying.set(false)
    }
  }

  protected async onRestart() {
    this.restarting.set(true)

    try {
      await this.api.restart()
      this.dialogs
        .open(
          'The VPS is rebooting. Please wait 1\u20132 minutes, then refresh the page.',
          {
            label: 'Rebooting',
          },
        )
        .subscribe()
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.restarting.set(false)
    }
  }

  protected async onLogout() {
    this.tasks.run(async () => {
      await this.api.logout()
      this.auth.authenticated.set(false)
      this.router.navigate(['/'])
    })
  }
}

// Whether any forward on `ip` covers port 80 (a DNAT range or an SNI/single
// entry) — the redirect and a port-80 forward are mutually exclusive.
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

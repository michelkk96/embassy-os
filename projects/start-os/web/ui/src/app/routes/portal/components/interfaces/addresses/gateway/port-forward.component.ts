import { Component, computed, inject, signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ErrorService, i18nPipe } from '@start9labs/shared'
import { T } from '@start9labs/start-core'
import { TuiButton, TuiDialogContext } from '@taiga-ui/core'
import { injectContext, PolymorpheusComponent } from '@taiga-ui/polymorpheus'
import { PatchDB } from 'patch-db-client'
import { of } from 'rxjs'
import { ApiService } from 'src/app/services/api/embassy-api.service'
import { DataModel } from 'src/app/services/patch-db/data-model'
import { renderPkgStatus } from 'src/app/services/pkg-status-rendering.service'
import { formatPortRange } from 'src/app/utils/format-port-range'
import { DnsGateway } from './domain-validation.component'
import {
  PortCheckField,
  PortCheckTestComponent,
} from './port-check-test.component'
import { TestStatusNoteComponent } from './test-status-note.component'

export type PortForwardValidationData = {
  gateway: DnsGateway
  port: number
  count: number
  packageId: string
  addSsl: boolean
  initialResults?: { portResult: T.CheckPortRes | null }
}

@Component({
  selector: 'port-forward-validation',
  template: `
    @let gatewayName =
      context.data.gateway.name || context.data.gateway.ipInfo.name;

    <h2>{{ 'Port Forwarding' | i18n }}</h2>
    <p>
      {{ 'In your gateway' | i18n }} "{{ gatewayName }}",
      {{ 'create this port forwarding rule' | i18n }}
    </p>

    <port-check-test
      [fields]="portFields"
      [testable]="!isRange"
      [result]="portResult()"
      [warningResult]="portResult()"
      [loading]="loading()"
      [disabled]="testDisabled()"
      (test)="testPort()"
    />

    @if (!isRange && testDisabled()) {
      @if (pkg(); as p) {
        <test-status-note [pkg]="p" />
      }
    }

    @if (!isManualMode) {
      <footer class="g-buttons padding-top">
        <button
          tuiButton
          appearance="flat"
          [disabled]="portOk()"
          (click)="context.completeWith()"
        >
          {{ 'Later' | i18n }}
        </button>
        <button
          tuiButton
          [disabled]="!portOk()"
          (click)="context.completeWith()"
        >
          {{ 'Done' | i18n }}
        </button>
      </footer>
    }
  `,
  styles: `
    h2 {
      margin: 2rem 0 0 0;
    }

    p {
      margin-top: 0.5rem;
    }

    .padding-top {
      padding-top: 2rem;
    }

    footer {
      margin-top: 1.5rem;
    }
  `,
  imports: [
    TuiButton,
    i18nPipe,
    TestStatusNoteComponent,
    PortCheckTestComponent,
  ],
})
export class PortForwardValidationComponent {
  private readonly errorService = inject(ErrorService)
  private readonly api = inject(ApiService)
  private readonly patch = inject<PatchDB<DataModel>>(PatchDB)

  readonly context =
    injectContext<TuiDialogContext<void, PortForwardValidationData>>()

  // The package's live status, or undefined for an OS interface (empty id). It
  // gates the tests and drives the status shown while a test is unavailable.
  protected readonly pkg = toSignal(
    this.context.data.packageId
      ? this.patch.watch$('packageData', this.context.data.packageId)
      : of(undefined),
  )
  protected readonly status = computed(() => {
    const pkg = this.pkg()
    return pkg ? renderPkgStatus(pkg).primary : 'running'
  })

  // A non-SSL binding is served directly by the service, so its port forward
  // can't be reached while the service is stopped. An SSL binding is fronted by
  // the always-up OS reverse proxy, so it stays testable.
  readonly testDisabled = computed(
    () => this.status() !== 'running' && !this.context.data.addSsl,
  )

  // A port range forwards a span of ports and can't be tested a port at a time.
  readonly isRange = this.context.data.count > 1
  readonly portDisplay = formatPortRange(
    this.context.data.port,
    this.context.data.count,
  )

  readonly portFields: readonly PortCheckField[] = this.isRange
    ? [
        { label: 'External Range', value: this.portDisplay },
        { label: 'Internal Range', value: this.portDisplay },
      ]
    : [
        { label: 'External Port', value: this.portDisplay },
        { label: 'Internal Port', value: this.portDisplay },
      ]

  readonly loading = signal(false)
  readonly portResult = signal<T.CheckPortRes | undefined>(undefined)

  readonly portOk = computed(() => {
    const result = this.portResult()
    return !!result?.openExternally && !!result?.hairpinning
  })

  readonly isManualMode = !this.context.data.initialResults

  constructor() {
    const initial = this.context.data.initialResults
    if (initial) {
      if (initial.portResult) this.portResult.set(initial.portResult)
    }
  }

  async testPort() {
    this.loading.set(true)

    try {
      const result = await this.api.checkPort({
        gateway: this.context.data.gateway.id,
        port: this.context.data.port,
      })

      this.portResult.set(result)
    } catch (e: any) {
      this.errorService.handleError(e)
    } finally {
      this.loading.set(false)
    }
  }
}

export const PORT_FORWARD_VALIDATION = new PolymorpheusComponent(
  PortForwardValidationComponent,
)

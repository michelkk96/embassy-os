import { Component, computed, input, output } from '@angular/core'
import { i18nKey, i18nPipe } from '@start9labs/shared'
import { T } from '@start9labs/start-core'
import { TuiButton } from '@taiga-ui/core'
import { TuiButtonLoading } from '@taiga-ui/kit'
import { PortCheckIconComponent } from 'src/app/routes/portal/components/port-check-icon.component'
import { PortCheckWarningsComponent } from 'src/app/routes/portal/components/port-check-warnings.component'
import { TableComponent } from 'src/app/routes/portal/components/table.component'

// One labelled value in the reachability-test row: a column in the desktop
// table and a field in the mobile card.
export type PortCheckField = { label: i18nKey; value: string }

// The shared external-reachability test row used by every Address Requirements
// modal — the IPv4 port forward and the IPv6 firewall in the domain modal, and
// the standalone port forward for a public IP. It renders the desktop table /
// mobile card, the status icon, the Test button, and the hairpinning warning;
// callers supply the labelled values and handle `(test)`.
@Component({
  selector: 'port-check-test',
  template: `
    <div class="desktop">
      <table [class.range-table]="!testable()" [appTable]="headers()">
        <tr>
          @if (testable()) {
            <td class="status">
              <port-check-icon [result]="result()" [loading]="loading()" />
            </td>
          }
          @for (field of fields(); track $index) {
            <td>{{ field.value }}</td>
          }
          @if (testable()) {
            <td>
              <button
                tuiButton
                size="s"
                [loading]="loading()"
                [disabled]="disabled()"
                (click)="test.emit()"
              >
                {{ 'Test' | i18n }}
              </button>
            </td>
          }
        </tr>
      </table>
    </div>
    <div class="mobile">
      <div class="card">
        @if (testable()) {
          <div class="card-status">
            <port-check-icon [result]="result()" [loading]="loading()" />
          </div>
        }
        <div class="card-fields">
          @for (field of fields(); track $index) {
            <div class="field">
              <span class="field-label">{{ field.label | i18n }}</span>
              <span>{{ field.value }}</span>
            </div>
          }
        </div>
        @if (testable()) {
          <button
            tuiButton
            size="s"
            [loading]="loading()"
            [disabled]="disabled()"
            (click)="test.emit()"
          >
            {{ 'Test' | i18n }}
          </button>
        }
      </div>
    </div>

    <port-check-warnings [result]="warningResult()" />
  `,
  styles: `
    .status {
      width: 3.2rem;
    }

    td:last-child {
      text-align: end;
    }

    // A range row has no status/Test columns, so its last cell is the internal
    // value — keep it left-aligned with its header.
    .range-table td:last-child {
      text-align: start;
    }

    .mobile {
      display: none;
    }

    .card {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 1rem;
      border: 1px solid var(--tui-border-normal);
      border-radius: var(--tui-radius-l);
      margin-top: 1rem;
    }

    .card-status {
      flex-shrink: 0;
      width: 1.5rem;
      text-align: center;
    }

    .card-fields {
      flex: 1;
      min-width: 0;
    }

    .field {
      display: flex;
      gap: 0.5rem;
    }

    .field-label {
      color: var(--tui-text-secondary);
      font: var(--tui-typography-body-s);

      &::after {
        content: ':';
      }
    }

    :host-context(tui-root._mobile) {
      .desktop {
        display: none;
      }

      .mobile {
        display: block;
      }
    }
  `,
  imports: [
    TuiButton,
    TuiButtonLoading,
    i18nPipe,
    TableComponent,
    PortCheckIconComponent,
    PortCheckWarningsComponent,
  ],
})
export class PortCheckTestComponent {
  // The labelled values to display (external/internal port, or an address).
  readonly fields = input.required<readonly PortCheckField[]>()
  // A port range is display-only — no reachability probe, hence no status icon
  // or Test button; its columns keep their range headers.
  readonly testable = input(true)
  readonly result = input<Pick<T.CheckPortRes, 'openExternally'>>()
  // When set, shows the hairpinning warning — IPv4 forwarding only; the IPv6
  // firewall has none.
  readonly warningResult = input<T.CheckPortRes>()
  readonly loading = input(false)
  readonly disabled = input(false)
  readonly test = output<void>()

  // A testable row brackets its value columns with a status icon and a Test
  // button; a range row shows only the columns.
  readonly headers = computed<Array<i18nKey | null>>(() => {
    const labels = this.fields().map(f => f.label)
    return this.testable() ? [null, ...labels, null] : [...labels]
  })
}

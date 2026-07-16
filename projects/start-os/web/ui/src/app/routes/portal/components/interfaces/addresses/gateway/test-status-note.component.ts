import { Component, computed, input } from '@angular/core'
import { i18nPipe } from '@start9labs/shared'
import { TuiIcon } from '@taiga-ui/core'
import { PackageDataEntry } from 'src/app/services/patch-db/data-model'
import {
  getStatusColor,
  PrimaryRendering,
  renderPkgStatus,
} from 'src/app/services/pkg-status-rendering.service'

// Shown in an Address Requirements modal when a reachability test needs the
// service running: a warning icon, the reason (plain text), and the service's
// live status rendered in its usual per-status color with animated dots for a
// transitional state.
@Component({
  selector: 'test-status-note',
  template: `
    <tui-icon class="g-warning" icon="@tui.triangle-alert" />
    <span>
      {{
        'Service must be running to perform this test. Current status:' | i18n
      }}
      <b [style.color]="color()">
        {{ statusText() | i18n }}
        @if (dots()) {
          <span class="g-dots"></span>
        }
      </b>
    </span>
  `,
  styles: `
    :host {
      display: flex;
      align-items: flex-start;
      gap: 0.5rem;
      margin-top: 0.5rem;
    }

    tui-icon {
      flex-shrink: 0;
      font-size: 1.25rem;
    }
  `,
  imports: [i18nPipe, TuiIcon],
})
export class TestStatusNoteComponent {
  readonly pkg = input.required<PackageDataEntry>()

  private readonly status = computed(() => renderPkgStatus(this.pkg()).primary)
  protected readonly statusText = computed(
    () => PrimaryRendering[this.status()].display,
  )
  protected readonly dots = computed(
    () => PrimaryRendering[this.status()].showDots,
  )

  protected readonly color = computed(() => getStatusColor(this.status()))
}

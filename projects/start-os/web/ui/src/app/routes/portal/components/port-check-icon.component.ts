import { Component, input } from '@angular/core'
import { T } from '@start9labs/start-core'
import { TuiIcon, TuiLoader } from '@taiga-ui/core'

@Component({
  selector: 'port-check-icon',
  template: `
    @if (loading()) {
      <tui-loader size="s" />
    } @else {
      @let res = result();
      @if (res) {
        @if (checkInternal() && !res.openInternally) {
          <tui-icon class="g-warning" icon="@tui.alert-triangle" />
        } @else if (!res.openExternally) {
          <tui-icon class="g-negative" icon="@tui.x" />
        } @else {
          <tui-icon class="g-positive" icon="@tui.check" />
        }
      } @else {
        <tui-icon class="g-secondary" icon="@tui.minus" />
      }
    }
  `,
  styles: `
    tui-icon {
      font-size: 1.3rem;
      vertical-align: text-bottom;
    }
  `,
  imports: [TuiIcon, TuiLoader],
})
export class PortCheckIconComponent {
  // Accepts either a full IPv4 check or the IPv6 sub-result — both carry the
  // openExternally / openInternally fields this reads.
  readonly result =
    input<Pick<T.CheckPortRes, 'openExternally' | 'openInternally'>>()
  readonly loading = input(false)
  // Surface the neutral "can't determine" cue from openInternally. Only the
  // System > Gateways port-forwards modal sets this — it's an aggregate with no
  // single service to status-watch, so the point-sample is its best signal. The
  // Address Requirements modals leave it off and rely on the whole-window watch.
  readonly checkInternal = input(false)
}

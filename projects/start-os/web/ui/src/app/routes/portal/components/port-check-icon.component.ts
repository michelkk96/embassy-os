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
        @if (res.openExternally) {
          <tui-icon class="g-positive" icon="@tui.check" />
        } @else if (!res.openInternally) {
          <tui-icon class="g-warning" icon="@tui.alert-triangle" />
        } @else {
          <tui-icon class="g-negative" icon="@tui.x" />
        }
      } @else {
        <tui-icon class="g-secondary" icon="@tui.minus" />
      }
    }
  `,
  styles: `
    tui-icon {
      font-size: 1rem;
    }
  `,
  imports: [TuiIcon, TuiLoader],
})
export class PortCheckIconComponent {
  // Either a full IPv4 check or the IPv6 sub-result; both carry the fields read
  // here. A reachable port is reported as such whatever the internal probe said
  // — something answered externally, so the probe was simply stale.
  readonly result = input<T.CheckPortRes | T.CheckPortV6Res>()
  readonly loading = input(false)
}

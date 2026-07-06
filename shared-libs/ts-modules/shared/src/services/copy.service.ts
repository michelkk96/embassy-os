import { Clipboard } from '@angular/cdk/clipboard'
import { inject, Service } from '@angular/core'
import { TuiNotificationService } from '@taiga-ui/core'

import { i18nPipe } from '../i18n/i18n.pipe'

@Service()
export class CopyService {
  private readonly clipboard = inject(Clipboard)
  private readonly i18n = inject(i18nPipe)
  private readonly alerts = inject(TuiNotificationService)

  async copy(text: string) {
    const success = this.clipboard.copy(text)
    const message = success ? 'Copied to clipboard' : 'Failed'
    const appearance = success ? 'positive' : 'negative'

    this.alerts.open(this.i18n.transform(message), { appearance }).subscribe()
  }
}

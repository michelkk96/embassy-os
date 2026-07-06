import { Component, inject, input } from '@angular/core'
import { DialogService, i18nPipe, TaskService } from '@start9labs/shared'
import { TuiButton, TuiNotificationService } from '@taiga-ui/core'
import { filter } from 'rxjs'
import { ApiService } from 'src/app/services/api/embassy-api.service'
import { BackupService } from './backup.service'

@Component({
  selector: 'backup-legacy-warning',
  template: `
    <button
      tuiButton
      size="s"
      iconStart="@tui.brush-cleaning"
      (click)="$event.stopPropagation(); remove()"
    >
      {{ 'Delete old backup' | i18n }}
    </button>
  `,
  styles: `
    :host {
      display: inline-flex;
    }
  `,
  imports: [TuiButton, i18nPipe],
})
export class BackupLegacyWarningComponent {
  private readonly dialog = inject(DialogService)
  private readonly alerts = inject(TuiNotificationService)
  private readonly tasks = inject(TaskService)
  private readonly api = inject(ApiService)
  private readonly service = inject(BackupService)
  private readonly i18n = inject(i18nPipe)

  readonly id = input.required<string>()

  remove() {
    this.dialog
      .openConfirm({
        label: 'Delete old backup?',
        size: 's',
        data: {
          content:
            'Permanently delete the old (V1) backup from this target? This cannot be undone. Your current (V2) backup will not be affected.',
          no: 'Cancel',
          yes: 'Delete',
        },
      })
      .pipe(filter(Boolean))
      .subscribe(() =>
        this.tasks.run(async () => {
          await this.api.deleteLegacyBackup({ targetId: this.id() })
          this.service.clearLegacy(this.id())
          this.alerts
            .open(this.i18n.transform('Old backup deleted'), {
              appearance: 'positive',
            })
            .subscribe()
        }, 'Deleting old backup'),
      )
  }
}

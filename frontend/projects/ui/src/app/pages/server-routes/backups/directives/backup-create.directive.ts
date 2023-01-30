import { Directive, HostListener } from '@angular/core'
import { LoadingController, ModalController } from '@ionic/angular'
import { ApiService } from 'src/app/services/api/embassy-api.service'
import { BackupSelectPage } from 'src/app/pages/server-routes/backups/components/backup-select/backup-select.page'
import { BackupDrivesComponent } from '../components/backup-drives/backup-drives.component'
import { MappedBackupTarget } from 'src/app/types/mapped-backup-target'
import {
  CifsBackupTarget,
  DiskBackupTarget,
} from 'src/app/services/api/api.types'

@Directive({
  selector: '[backupCreate]',
})
export class BackupCreateDirective {
  serviceIds: string[] = []

  constructor(
    private readonly loadingCtrl: LoadingController,
    private readonly modalCtrl: ModalController,
    private readonly embassyApi: ApiService,
  ) {}

  @HostListener('click') onClick() {
    this.presentModalTarget()
  }

  async presentModalTarget() {
    const modal = await this.modalCtrl.create({
      presentingElement: await this.modalCtrl.getTop(),
      component: BackupDrivesComponent,
      componentProps: { type: 'create' },
    })

    modal
      .onDidDismiss<MappedBackupTarget<CifsBackupTarget | DiskBackupTarget>>()
      .then(res => {
        if (res.data) {
          this.presentModalSelect(res.data.id)
        }
      })

    await modal.present()
  }

  private async presentModalSelect(targetId: string) {
    const modal = await this.modalCtrl.create({
      presentingElement: await this.modalCtrl.getTop(),
      component: BackupSelectPage,
      componentProps: {
        btnText: 'Create Backup',
      },
    })

    modal.onWillDismiss().then(res => {
      if (res.data) {
        this.createBackup(targetId, res.data)
      }
    })

    await modal.present()
  }

  private async createBackup(
    targetId: string,
    pkgIds: string[],
  ): Promise<void> {
    const loader = await this.loadingCtrl.create({
      message: 'Beginning backup...',
    })
    await loader.present()

    await this.embassyApi
      .createBackup({
        'target-id': targetId,
        'package-ids': pkgIds,
      })
      .finally(() => loader.dismiss())
  }
}

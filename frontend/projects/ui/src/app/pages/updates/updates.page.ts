import { Component, Inject } from '@angular/core'
import { ApiService } from 'src/app/services/api/embassy-api.service'
import { PatchDB } from 'patch-db-client'
import {
  DataModel,
  PackageDataEntry,
  PackageState,
} from 'src/app/services/patch-db/data-model'
import { MarketplaceService } from 'src/app/services/marketplace.service'
import {
  AbstractMarketplaceService,
  Marketplace,
  MarketplaceManifest,
  MarketplacePkg,
  StoreIdentity,
} from '@start9labs/marketplace'
import { Emver, isEmptyObject, sameUrl } from '@start9labs/shared'
import { Pipe, PipeTransform } from '@angular/core'
import { combineLatest, map, Observable } from 'rxjs'
import {
  AlertController,
  LoadingController,
  NavController,
} from '@ionic/angular'
import { hasCurrentDeps } from 'src/app/util/has-deps'
import { getAllPackages } from 'src/app/util/get-package-data'
import { Breakages } from 'src/app/services/api/api.types'
import { ClientStorageService } from 'src/app/services/client-storage.service'
import { ConfigService } from 'src/app/services/config.service'

interface UpdatesData {
  hosts: StoreIdentity[]
  marketplace: Marketplace
  localPkgs: Record<string, PackageDataEntry>
  errors: string[]
}

@Component({
  selector: 'updates',
  templateUrl: 'updates.page.html',
  styleUrls: ['updates.page.scss'],
})
export class UpdatesPage {
  readonly hosts$ = combineLatest([
    this.clientStorageService.showDevTools$,
    this.marketplaceService.getKnownHosts$(),
  ]).pipe(
    map(([devMode, knownHosts]) => {
      if (devMode) return knownHosts
      return knownHosts.filter(h => {
        const { alpha, beta } = this.config.marketplace
        return ![alpha, beta].includes(h.url as any)
      })
    }),
  )

  readonly data$: Observable<UpdatesData> = combineLatest({
    hosts: this.hosts$,
    marketplace: this.marketplaceService.getMarketplace$(),
    localPkgs: this.patch.watch$('package-data'),
    errors: this.marketplaceService.getRequestErrors$(),
  })

  readonly PackageState = PackageState

  constructor(
    @Inject(AbstractMarketplaceService)
    readonly marketplaceService: MarketplaceService,
    private readonly api: ApiService,
    private readonly patch: PatchDB<DataModel>,
    private readonly navCtrl: NavController,
    private readonly loadingCtrl: LoadingController,
    private readonly alertCtrl: AlertController,
    private readonly clientStorageService: ClientStorageService,
    private readonly config: ConfigService,
  ) {}

  viewInMarketplace(pkg: PackageDataEntry) {
    const url = pkg.installed?.['marketplace-url']
    const queryParams = url ? { url } : {}

    this.navCtrl.navigateForward([`marketplace/${pkg.manifest.id}`], {
      queryParams,
    })
  }

  async tryUpdate(
    manifest: MarketplaceManifest,
    url: string,
    local: PackageDataEntry,
  ): Promise<void> {
    const { id, version } = manifest

    delete this.marketplaceService.updateErrors[id]
    this.marketplaceService.updateQueue[id] = true

    if (hasCurrentDeps(local)) {
      this.dryUpdate(manifest, url)
    } else {
      this.update(id, version, url)
    }
  }

  private async dryUpdate(manifest: MarketplaceManifest, url: string) {
    const loader = await this.loadingCtrl.create({
      message: 'Checking dependent services...',
    })
    await loader.present()

    const { id, version } = manifest

    try {
      const breakages = await this.api.dryUpdatePackage({
        id,
        version: `${version}`,
      })
      await loader.dismiss()

      if (isEmptyObject(breakages)) {
        this.update(id, version, url)
      } else {
        const proceed = await this.presentAlertBreakages(
          manifest.title,
          breakages,
        )
        if (proceed) {
          this.update(id, version, url)
        } else {
          delete this.marketplaceService.updateQueue[id]
        }
      }
    } catch (e: any) {
      delete this.marketplaceService.updateQueue[id]
      this.marketplaceService.updateErrors[id] = e.message
    }
  }

  private async presentAlertBreakages(
    title: string,
    breakages: Breakages,
  ): Promise<boolean> {
    let message: string = `As a result of updating ${title}, the following services will no longer work properly and may crash:<ul>`
    const localPkgs = await getAllPackages(this.patch)
    const bullets = Object.keys(breakages).map(id => {
      const title = localPkgs[id].manifest.title
      return `<li><b>${title}</b></li>`
    })
    message = `${message}${bullets.join('')}</ul>`

    return new Promise(async resolve => {
      const alert = await this.alertCtrl.create({
        header: 'Warning',
        message,
        buttons: [
          {
            text: 'Cancel',
            role: 'cancel',
            handler: () => {
              resolve(false)
            },
          },
          {
            text: 'Continue',
            handler: () => {
              resolve(true)
            },
            cssClass: 'enter-click',
          },
        ],
        cssClass: 'alert-warning-message',
      })

      await alert.present()
    })
  }

  private async update(id: string, version: string, url: string) {
    try {
      await this.marketplaceService.installPackage(id, version, url)
    } catch (e: any) {
      delete this.marketplaceService.updateQueue[id]
      this.marketplaceService.updateErrors[id] = e.message
    }
  }
}

@Pipe({
  name: 'filterUpdates',
})
export class FilterUpdatesPipe implements PipeTransform {
  constructor(private readonly emver: Emver) {}

  transform(
    pkgs: MarketplacePkg[],
    local: Record<string, PackageDataEntry> = {},
    url: string,
  ): MarketplacePkg[] {
    return pkgs.filter(
      ({ manifest }) =>
        marketplaceSame(manifest, local, url) &&
        versionLower(manifest, local, this.emver),
    )
  }
}

export function marketplaceSame(
  { id }: MarketplaceManifest,
  local: Record<string, PackageDataEntry>,
  url: string,
): boolean {
  const localUrl = local[id]?.installed?.['marketplace-url']
  return sameUrl(localUrl, url)
}

export function versionLower(
  { version, id }: MarketplaceManifest,
  local: Record<string, PackageDataEntry>,
  emver: Emver,
): boolean {
  return (
    local[id].state === PackageState.Updating ||
    emver.compare(version, local[id].installed?.manifest.version || '') === 1
  )
}

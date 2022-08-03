import { DOCUMENT } from '@angular/common'
import { Component, Inject, ViewChild } from '@angular/core'
import { IonContent } from '@ionic/angular'
import { map, takeUntil, timer } from 'rxjs'
import { WebSocketSubjectConfig } from 'rxjs/webSocket'
import {
  DestroyService,
  toLocalIsoString,
  Log,
  getPkgId,
} from '@start9labs/shared'
import { ApiService } from 'src/app/services/api/embassy-api.service'
import { ActivatedRoute } from '@angular/router'

var Convert = require('ansi-to-html')
var convert = new Convert({
  newline: true,
  bg: 'transparent',
  colors: {
    4: 'Cyan',
  },
  escapeXML: true,
})

@Component({
  selector: 'app-show-logs',
  templateUrl: './app-show-logs.component.html',
  styleUrls: ['./app-show-logs.component.scss'],
  providers: [DestroyService],
})
export class AppShowLogsComponent {
  @ViewChild('logsContent')
  private readonly logsContent?: IonContent
  private readonly pkgId = getPkgId(this.route)
  loading = true
  logsError = ''
  toProcess: Log[] = []

  constructor(
    @Inject(DOCUMENT) private readonly document: Document,
    private readonly route: ActivatedRoute,
    private readonly destroy$: DestroyService,
    private readonly api: ApiService,
  ) {}

  async ngOnInit() {
    try {
      const { guid } = await this.api.followPackageLogs({
        id: this.pkgId,
        limit: 10,
      })

      const host = this.document.location.host
      const protocol =
        this.document.location.protocol === 'http:' ? 'ws' : 'wss'

      const config: WebSocketSubjectConfig<Log> = {
        url: `${protocol}://${host}/ws/rpc/${guid}`,
        openObserver: {
          next: () => {
            this.processJob()
          },
        },
      }

      this.api
        .openLogsWebsocket$(config)
        .pipe(takeUntil(this.destroy$))
        .subscribe({
          next: msg => {
            this.toProcess.push(msg)
          },
        })
    } catch (e: any) {
      this.logsError = 'failed to load logs'
    } finally {
      this.loading = false
    }
  }

  private processJob() {
    timer(100, 500)
      .pipe(
        map((_, index) => index),
        takeUntil(this.destroy$),
      )
      .subscribe(index => {
        console.log('HERERERE', index)
        this.processRes(index)
        this.toProcess = []
      })
  }

  private processRes(index: number) {
    if (!this.toProcess.length) return

    const container = document.getElementById('app-logs-container')
    const newLogs = document.getElementById('app-logs-template')?.cloneNode()

    if (!(newLogs instanceof HTMLElement)) return

    newLogs.innerHTML = this.convertToAnsi()

    container?.append(newLogs)

    if (index > 10) {
      const first = container?.firstChild
      if (first) container.removeChild(first)
    }

    // scroll to bottom
    setTimeout(() => {
      this.logsContent?.scrollToBottom(250)
    }, 25)
  }

  private convertToAnsi() {
    return this.toProcess
      .map(
        log =>
          `<span style="color: #FFF; font-weight: bold;">${toLocalIsoString(
            new Date(log.timestamp),
          )}</span>&nbsp;&nbsp;${convert.toHtml(log.message)}`,
      )
      .join('<br />')
  }
}

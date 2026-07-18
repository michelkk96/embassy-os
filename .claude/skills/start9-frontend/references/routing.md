# Routing

- Routes are flat arrays of **lazy default exports**: `loadComponent: () => import('./routes/x')`
  (no `.then` — components are `export default class`), `loadChildren: () => import('./x/routes')`
  where the child file ends `export default [ … ] satisfies Routes`. Eager `component:` only for
  shells.
- **Never `providers` on a route.** A subtree that needs scoped services gets a shell component
  (`component: Outlet` wrapping `<router-outlet />` with the providers) — see start-wrt
  `devices/`.
- Guards: **inline `canMatch` arrows** — `canMatch: [() => inject(AuthService).authenticated()]`;
  start-wrt's four same-path `''` routes discriminate purely by `canMatch` (wizard/setup/app/
  login). Class guards are legacy. Dashboards use none at all — an `AdminShell` component gates
  by `adminService.token()`.
- Titles where they matter (public sites): per-route `title:` + a `TitleStrategy` subclass
  ("StartTunnel – X"), or StartOS's `titleResolver` composing "server — page". Embedded UIs
  skip titles.
- `{ path: '**', redirectTo: … }` at every level (wildcard, not `''`+`pathMatch`).
- Navigation: `routerLink` in templates (with `[queryParams]`, `[state]`), `Router.navigate` in
  TS; shareable UI state lives in **query params**, synced bidirectionally (see components.md, templates).


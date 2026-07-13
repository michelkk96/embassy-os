import * as T from '@start9labs/start-core/types'
import '@start9labs/start-core/interfaces/ServiceInterfaceBuilder'
import '@start9labs/start-core/interfaces/Origin'

/** Default time in milliseconds to wait for a process to exit after SIGTERM before escalating to SIGKILL */
export const DEFAULT_SIGTERM_TIMEOUT = 60_000
/**
 * Used to ensure that the main function is running with the valid proofs.
 * We first do the folowing order of things
 * 1. We get the interfaces
 * 2. We setup all the commands to setup the system
 * 3. We create the health checks
 * 4. We setup the daemons init system
 *
 * `fn` returns any {@link T.DaemonBuildable} — a static `Daemons.of(...)` chain,
 * or the reconciler from `Daemons.dynamic(effects, ...)` for a daemon set that
 * changes at runtime. `main` is always `setupMain`; the choice of static vs
 * reactive is what you return from it.
 * @param fn
 * @returns
 */
export const setupMain = <Manifest extends T.SDKManifest>(
  fn: (o: { effects: T.Effects }) => Promise<T.DaemonBuildable>,
): T.ExpectedExports.main => {
  return async options => {
    const result = await fn(options)
    return result
  }
}

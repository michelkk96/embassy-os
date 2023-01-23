use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use bollard::container::{KillContainerOptions, StopContainerOptions};
use color_eyre::eyre::eyre;
use embassy_container_init::{ProcessGroupId, SignalGroupParams};
use futures::{future::BoxFuture, FutureExt};
use helpers::UnixRpcClient;
use models::{ErrorKind, ResultExt};
use nix::sys::signal::Signal;
use patch_db::DbHandle;
use sqlx::Executor;
use tokio::spawn;
use tokio::sync::watch::error::RecvError;
use tokio::sync::watch::{channel, Receiver, Sender};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use torut::onion::TorSecretKeyV3;
use tracing::instrument;

use crate::net::interface::InterfaceId;
use crate::net::GeneratedCertificateMountPoint;
use crate::procedure::docker::{DockerContainer, DockerProcedure, LongRunning};
#[cfg(feature = "js_engine")]
use crate::procedure::js_scripts::JsProcedure;
use crate::procedure::{NoOutput, PackageProcedure, ProcedureName};
use crate::s9pk::manifest::Manifest;
use crate::util::{ApplyRef, Container, NonDetachingJoinHandle};
use crate::Error;
use crate::{context::RpcContext, util::actor::Actor};
use crate::{manager::sync::synchronizer, status::MainStatus};

pub mod health;
pub mod manager_map;
mod sync;

type ManagerActor = Arc<Actor<ManagerState>>;
type ManagerRunDocker = Result<Result<NoOutput, (i32, String)>, Error>;
type ManagerPersistantContainer = Option<Arc<PersistentContainer>>;
struct RunMain {
    handle: NonDetachingJoinHandle<()>,
    callback_done: mpsc::UnboundedSender<oneshot::Sender<()>>,
    response: BoxFuture<'static, Option<ManagerRunDocker>>,
}
impl RunMain {
    fn main(handle: impl Future<Output = ManagerRunDocker>) -> Self {
        let (callback_done, receiver) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
        let (response_sender, response) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let res = handle.await;
            if let Ok(res) = res {
                while let Some(sender) = receiver.recv().await {
                    sender.send(());
                }
                response_sender.send(Some(res));
            } else {
                response_sender.send(None);
            }
        })
        .into();
        let response = (async move { response.await.ok().flatten() }).boxed::<'static>();
        RunMain {
            handle,
            callback_done,
            response,
        }
    }
    fn is_done(&self) -> BoxFuture<'static, ()> {
        let (sender, receiver) = oneshot::channel();
        if let Err(err) = self.callback_done.send(sender) {
            tracing::error!("Sending a callback done");
            tracing::debug!("{err:?}");
            return futures::future::ready(()).boxed();
        }
        (async move {
            receiver.await;
        })
        .boxed()
    }
    async fn into_response(self) -> Option<ManagerRunDocker> {
        self.response.await
    }
}

pub const SOFT_KILL: u8 = 9;
pub const HEALTH_CHECK_COOLDOWN_SECONDS: u64 = 15;
pub const HEALTH_CHECK_GRACE_PERIOD_SECONDS: u64 = 5;

struct ManagerSeed {
    ctx: RpcContext,
    manifest: Manifest,
    container_name: String,
    tor_keys: BTreeMap<InterfaceId, TorSecretKeyV3>,
}

impl ManagerSeed {
    async fn stop_container(&self) -> Result<(), Error> {
        match self
            .ctx
            .docker
            .stop_container(
                &self.container_name,
                Some(StopContainerOptions {
                    t: sigterm_timeout(&self.manifest)
                        .map(|d| d.as_secs())
                        .unwrap_or(30) as i64,
                }),
            )
            .await
        {
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, // NOT FOUND
                ..
            })
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 409, // CONFLICT
                ..
            })
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, // NOT MODIFIED
                ..
            }) => (), // Already stopped
            a => a?,
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum StartStop {
    Start,
    Stop,
}

enum ManagerRunning {}

// TODO BLUJ Need to have a signal to soft kill -9 running docker RUNNING, starting.
enum ManagerStates {
    Stopped,
    Running {
        run_main: RunMain,
    },
    Starting {
        run_main: RunMain,
        transition: JoinHandle<()>,
    },
    Stopping {
        run_main: RunMain,
        transition: JoinHandle<()>,
    },
    Configuring {
        start_stop: StartStop,
        transition: JoinHandle<()>,
    },
    ConfiguringStopping {
        start_stop: StartStop,
        run_main: RunMain,
        transition: JoinHandle<()>,
    },
    BackingUp {
        start_stop: StartStop,
        transition: JoinHandle<()>,
    },
    BackingUpStopping {
        start_stop: StartStop,
        run_main: RunMain,
        transition: JoinHandle<()>,
    },
    RestartingStopping {
        start_stop: StartStop,
        run_main: RunMain,
        transition: JoinHandle<()>,
    },
}

impl ManagerStates {
    fn take(&mut self) -> Self {
        let mut other = ManagerStates::Stopped;
        std::mem::swap(self, &mut other);
        other
    }

    fn into_components(self) -> (Option<RunMain>, Option<JoinHandle<()>>) {
        match self {
            ManagerStates::Stopped => (None, None),
            ManagerStates::Running { run_main } => (Some(run_main), None),
            ManagerStates::Starting {
                run_main,
                transition,
            } => (Some(run_main), Some(transition)),
            ManagerStates::Stopping {
                run_main,
                transition,
            } => (Some(run_main), Some(transition)),
            ManagerStates::Configuring {
                start_stop,
                transition,
            } => (None, Some(transition)),
            ManagerStates::ConfiguringStopping {
                start_stop,
                run_main,
                transition,
            } => (Some(run_main), Some(transition)),
            ManagerStates::BackingUp {
                start_stop,
                transition,
            } => (None, Some(transition)),
            ManagerStates::BackingUpStopping {
                start_stop,
                run_main,
                transition,
            } => (Some(run_main), Some(transition)),
            ManagerStates::RestartingStopping {
                start_stop,
                run_main,
                transition,
            } => (Some(run_main), Some(transition)),
        }
    }
}
struct ManagerState {
    seed: Arc<ManagerSeed>,
    state: ManagerStates,
}

#[derive(Clone)]
struct Manager {
    actor: ManagerActor,
    persistent_container: ManagerPersistantContainer,
}

impl Manager {
    #[instrument(skip(ctx))]
    pub async fn new(
        ctx: RpcContext,
        manifest: Manifest,
        tor_keys: BTreeMap<InterfaceId, TorSecretKeyV3>,
    ) -> Result<Self, Error> {
        let mut seed = Arc::new(ManagerSeed {
            ctx,
            container_name: DockerProcedure::container_name(&manifest.id, None),
            manifest,
            tor_keys,
        });

        let persistent_container = PersistentContainer::init(&seed).await?;
        /// TODO BLUJ Deal With starting
        let state = ManagerStates::Stopped;
        Ok(Self {
            actor: Arc::new(Actor::new(ManagerState { seed, state })),
            persistent_container,
        })
    }
    pub async fn start(&self) -> Result<(), Error> {
        let manager = self.clone();
        let persistant_container = self.persistent_container.clone();
        self.actor
            .async_event(|state| {
                async move {
                    /// TODO BLUJ Refactor
                    match &state.state {
                        ManagerStates::Stopped => (),
                        ManagerStates::Running { .. }
                        | ManagerStates::Starting { .. }
                        | ManagerStates::RestartingStopping { .. } => return Ok::<_, Error>(()),
                        // TODO BLUJ This is special, deal with
                        ManagerStates::Stopping { .. }
                        | ManagerStates::Configuring { .. }
                        | ManagerStates::BackingUp { .. }
                        | ManagerStates::BackingUpStopping { .. }
                        | ManagerStates::ConfiguringStopping { .. } => (),
                    }
                    let seed = state.seed.clone();
                    let (started, run_main) = run_main(seed, persistant_container);
                    let transition = tokio::spawn(async move {
                        if let Some(IsStarted) = started.await {
                            manager.staring_done();
                        } else {
                            manager.restart();
                        }
                    });

                    state.state = ManagerStates::Starting {
                        run_main,
                        transition,
                    };
                    Ok(())
                }
                .boxed()
            })
            .await
            .with_kind(ErrorKind::Unknown)??;
        Ok(())
    }
    pub async fn stop(&self) -> Result<(), Error> {
        let manager = self.clone();
        self.actor
            .async_event(
                |state| -> std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
                    async move {
                        // Will be needing the running main?
                        let run_main = match state.state.take() {
                            ManagerStates::Stopped => {
                                state.state = ManagerStates::Stopped;
                                return Ok::<_, Error>(());
                            }
                            ManagerStates::Configuring {
                                start_stop,
                                transition,
                            }
                            | ManagerStates::BackingUp {
                                start_stop,
                                transition,
                            } => {
                                transition.abort();
                                return Ok(());
                            }
                            stopping @ ManagerStates::Stopping { .. } => {
                                state.state = stopping;
                                return Ok(());
                            }
                            ManagerStates::Running { run_main } => {
                                state.seed.stop_container().await?;
                                run_main
                            }
                            ManagerStates::Starting {
                                run_main,
                                transition,
                            } => {
                                transition.abort();
                                state.seed.stop_container().await?;
                                run_main
                            }
                            ManagerStates::BackingUpStopping {
                                start_stop,
                                transition,
                                run_main,
                            }
                            | ManagerStates::ConfiguringStopping {
                                start_stop,
                                run_main,
                                transition,
                            }
                            | ManagerStates::RestartingStopping {
                                start_stop,
                                transition,
                                run_main,
                            } => {
                                transition.abort();
                                run_main
                            }
                        };
                        let seed = state.seed.clone();
                        let is_done = run_main.is_done();
                        let transition = tokio::spawn(async move {
                            if let Err(_) = tokio::time::timeout(
                                Duration::from_secs(
                                    sigterm_timeout(&seed.manifest)
                                        .map(|d| d.as_secs())
                                        .unwrap_or(30),
                                ),
                                is_done,
                            )
                            .await
                            {
                                tracing::warn!(
                                    "Timed out waiting for docker to stop our main thread"
                                );
                                // Ok(Err(e)) => {
                                //     tracing::error!(
                                //         "Docker join error {container_name}",
                                //         container_name = seed.container_name
                                //     );
                                //     tracing::debug!("{e:?}");
                                // }
                                // Ok(Ok(Err(e))) => {
                                //     tracing::error!(
                                //         "Docker container {container_name} run time error",
                                //         container_name = seed.container_name
                                //     );
                                //     tracing::debug!("{e:?}");
                                // }
                                // Ok(Ok(Ok(_))) => (),
                            }
                            manager.stopping_done().await;
                        });
                        state.state = ManagerStates::Stopping {
                            transition,
                            run_main,
                        };
                        Ok(())
                    }
                    .boxed()
                },
            )
            .await
            .with_kind(ErrorKind::Unknown)??;
        Ok(())
    }
    pub async fn restart(&self) -> Result<(), Error> {
        let manager = self.clone();
        self.actor
            .async_event(|state| {
                async move {
                    // Will be needing the running main?
                    let run_main = match state.state.take() {
                        restarting @ ManagerStates::RestartingStopping { .. } => {
                            state.state = restarting;
                            return Ok(());
                        }
                        ManagerStates::Stopped => {
                            tokio::spawn({
                                async move {
                                    manager.start().await;
                                }
                            });
                            return Ok::<_, Error>(());
                        }
                        ManagerStates::BackingUp {
                            start_stop,
                            transition,
                        }
                        | ManagerStates::Configuring {
                            start_stop,
                            transition,
                        } => {
                            transition.abort();
                            tokio::spawn({
                                async move {
                                    manager.start().await;
                                }
                            });
                            return Ok::<_, Error>(());
                        }
                        ManagerStates::Stopping {
                            transition,
                            run_main,
                        }
                        | ManagerStates::ConfiguringStopping {
                            start_stop: _,
                            run_main,
                            transition,
                        }
                        | ManagerStates::BackingUpStopping {
                            start_stop: _,
                            run_main,
                            transition,
                        } => {
                            transition.abort();
                            run_main
                        }
                        ManagerStates::Running { run_main } => {
                            state.seed.stop_container().await?;
                            run_main
                        }
                        ManagerStates::Starting {
                            run_main,
                            transition,
                        } => {
                            transition.abort();
                            state.seed.stop_container().await?;
                            run_main
                        }
                    };
                    let seed = state.seed.clone();
                    let is_done = run_main.is_done();
                    let transition = tokio::spawn(async move {
                        if let Err(err) = tokio::time::timeout(
                            Duration::from_secs(
                                sigterm_timeout(&seed.manifest)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(30),
                            ),
                            is_done,
                        )
                        .await
                        {
                            tracing::warn!("Timed out waiting for docker to stop our main thread");
                        }
                        manager.restarting_done().await;
                    });
                    state.state = ManagerStates::RestartingStopping {
                        start_stop: StartStop::Start,
                        transition,
                        run_main,
                    };
                    Ok(())
                }
                .boxed()
            })
            .await
            .with_kind(ErrorKind::Unknown)??;
        Ok(())
    }
    pub async fn configure(&self) -> Result<(), Error> {
        todo!()
    }
    pub async fn backup(&self) -> Result<(), Error> {
        todo!()
    }
    pub async fn kill(self) -> Result<(), Error> {
        self.actor
            .async_event(|state| {
                async move {
                    let (run_main, transition) = state.state.take().into_components();
                    if let Some(transition) = transition {
                        transition.abort();
                    }
                    if let Some(run_main) = run_main {
                        state.seed.stop_container().await?;
                        if let Some(a) = run_main.into_response().await {
                            a?;
                        }
                    }
                    Ok::<(), Error>(())
                }
                .boxed()
            })
            .await
            .with_kind(ErrorKind::Unknown)??;

        // Stop
        // Wait for stop
        todo!()
    }

    async fn staring_done(&self) -> Result<(), Error> {
        todo!()
    }
    async fn stopping_done(&self) -> Result<(), Error> {
        todo!()
    }
    async fn restarting_done(&self) -> Result<(), Error> {
        todo!()
    }
}

struct IsRunning;
fn run_main(
    seed: Arc<ManagerSeed>,
    persistant_container: ManagerPersistantContainer,
) -> (BoxFuture<'static, Option<IsRunning>>, RunMain) {
    let (send, recv) = oneshot::channel();
    (
        recv.map(|x| x.ok()).boxed(),
        RunMain::new(async move {
            let interfaces = main_interfaces(&seed)?;
            let generated_certificate = generate_certificate(&*seed, &interfaces).await?;

            let mut runtime = NonDetachingJoinHandle::from(tokio::spawn(start_up_image(
                seed.clone(),
                generated_certificate,
            )));
            let ip = match persistant_container.is_some() {
                false => Some(match get_running_ip(&seed, &mut runtime).await {
                    GetRunningIp::Ip(x) => x,
                    GetRunningIp::Error(e) => return Err(e),
                    GetRunningIp::EarlyExit(x) => return Ok(x),
                }),
                true => None,
            };
            if let Some(ip) = ip {
                add_network_for_main(&seed, ip, interfaces, generated_certificate).await?;
            }

            send.send(IsRunning);
            let health = main_health_check_daemon(seed.clone());
            let res = tokio::select! {
                a = runtime => a.map_err(|_| Error::new(eyre!("Manager runtime panicked!"), crate::ErrorKind::Docker)).and_then(|a| a),
                _ = health => Err(Error::new(eyre!("Health check daemon exited!"), crate::ErrorKind::Unknown)),
            };
            if let Some(ip) = ip {
                remove_network_for_main(&*seed, ip).await?;
            }
            res
        }),
    )
}
async fn set_status(seed: &ManagerSeed, status: &MainStatus) -> Result<(), Error> {
    let mut db = seed.ctx.db.handle();
    crate::db::DatabaseModel::new()
        .package_data()
        .idx_model(&seed.manifest.id)
        .expect(&mut db)
        .await?
        .installed()
        .expect(&mut db)
        .await?
        .status()
        .main()
        .put(&mut db, status)
        .await?;
    Ok(())
}
async fn get_status(seed: &ManagerSeed) -> Result<MainStatus, Error> {
    let mut db = seed.ctx.db.handle();
    Ok(crate::db::DatabaseModel::new()
        .package_data()
        .idx_model(&seed.manifest.id)
        .expect(&mut db)
        .await?
        .installed()
        .expect(&mut db)
        .await?
        .status()
        .main()
        .get(&mut db)
        .await?
        .clone())
}

// States
// Desired/ actual
// - running
// - stopped
// Jobs
// -none
// -starting
// -stopping
// -configuring
// -backing-up
// -restarting
//
// Actions:
// - start
// - stop
// - restart
// - kill
// - pause
// - configure

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    Starting,
    Running,
    Stopped,
    Paused,
    Shutdown,
}

pub struct ManagerSharedState {
    seed: Arc<ManagerSeed>,
    persistent_container: Option<PersistentContainer>,
    status: (Sender<Status>, Receiver<Status>),
    killer: Notify,
    on_stop: Sender<OnStop>,
    synchronized: Notify,
    synchronize_now: Notify,
    commit_health_check_results: AtomicBool,
    next_gid: AtomicU32,
    main_gid: (Sender<ProcessGroupId>, Receiver<ProcessGroupId>),
}

#[derive(Debug, Clone, Copy)]
pub enum OnStop {
    Restart,
    Sleep,
    Exit,
}

/// We want to start up the manifest, but in this case we want to know that we have generated the certificates.
/// Note for _generated_certificate: Needed to know that before we start the state we have generated the certificate
async fn start_up_image(
    seed: Arc<ManagerSeed>,
    _generated_certificate: GeneratedCertificateMountPoint,
) -> Result<Result<NoOutput, (i32, String)>, Error> {
    seed.manifest
        .main
        .execute::<(), NoOutput>(
            &seed.ctx,
            &seed.manifest.id,
            &seed.manifest.version,
            ProcedureName::Main,
            &seed.manifest.volumes,
            None,
            None,
        )
        .await
}

impl Manager {
    #[instrument(skip(ctx))]
    async fn create(
        ctx: RpcContext,
        manifest: Manifest,
        tor_keys: BTreeMap<InterfaceId, TorSecretKeyV3>,
    ) -> Result<Self, Error> {
        let (on_stop, recv) = channel(OnStop::Sleep);
        let seed = Arc::new(ManagerSeed {
            ctx,
            container_name: DockerProcedure::container_name(&manifest.id, None),
            manifest,
            tor_keys,
        });
        let persistent_container = PersistentContainer::init(&seed).await?;
        let shared = Arc::new(ManagerSharedState {
            seed,
            persistent_container,
            status: channel(Status::Stopped),
            killer: Notify::new(),
            on_stop,
            synchronized: Notify::new(),
            synchronize_now: Notify::new(),
            commit_health_check_results: AtomicBool::new(true),
            next_gid: AtomicU32::new(1),
            main_gid: channel(ProcessGroupId(0)),
        });
        shared.synchronize_now.notify_one();
        let thread_shared = shared.clone();
        let thread = NonDetachingJoinHandle::from(tokio::spawn(async move {
            tokio::select! {
                _ = manager_thread_loop(recv, &thread_shared) => (),
                _ = synchronizer(&*thread_shared) => (),
            }
        }));
        Ok(Manager {
            shared,
            thread: Container::new(Some(thread)),
        })
    }

    pub async fn signal(&self, signal: &Signal) -> Result<(), Error> {
        send_signal(&self.shared, signal).await
    }

    #[instrument(skip(self))]
    async fn exit(&self) -> Result<(), Error> {
        self.shared
            .commit_health_check_results
            .store(false, Ordering::SeqCst);
        let _ = self.shared.on_stop.send(OnStop::Exit);

        match self
            .shared
            .seed
            .ctx
            .docker
            .stop_container(
                &self.shared.seed.container_name,
                Some(StopContainerOptions {
                    t: sigterm_timeout(&self.shared.seed.manifest)
                        .map(|d| d.as_secs())
                        .unwrap_or(30) as i64,
                }),
            )
            .await
        {
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, // NOT FOUND
                ..
            })
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 409, // CONFLICT
                ..
            })
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 304, // NOT MODIFIED
                ..
            }) => (), // Already stopped
            a => a?,
        };
        self.shared.killer.notify_waiters();

        if let Some(thread) = self.thread.take().await {
            thread.await.map_err(|e| {
                Error::new(
                    eyre!("Manager thread panicked: {}", e),
                    crate::ErrorKind::Docker,
                )
            })?;
        }
        Ok(())
    }
    /// this will depend on locks to main status. if you hold any locks when calling this function that conflict, this will deadlock
    pub async fn synchronize(&self) {
        self.shared.synchronize_now.notify_waiters();
        self.shared.synchronized.notified().await
    }

    pub fn new_gid(&self) -> ProcessGroupId {
        ProcessGroupId(
            self.shared
                .next_gid
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        )
    }

    pub fn new_main_gid(&self) -> ProcessGroupId {
        let gid = self.new_gid();
        self.shared.main_gid.0.send_modify(|x| *x = gid);
        gid
    }

    pub fn rpc_client(&self) -> Option<Arc<UnixRpcClient>> {
        self.shared
            .persistent_container
            .as_ref()
            .map(|c| c.rpc_client.borrow().clone())
    }
}

async fn manager_thread_loop(mut recv: Receiver<OnStop>, thread_shared: &Arc<ManagerSharedState>) {
    loop {
        fn handle_stop_action<'a>(
            recv: &'a mut Receiver<OnStop>,
        ) -> (
            OnStop,
            Option<impl Future<Output = Result<(), RecvError>> + 'a>,
        ) {
            let val = *recv.borrow_and_update();
            match val {
                OnStop::Sleep => (OnStop::Sleep, Some(recv.changed())),
                a => (a, None),
            }
        }
        let (stop_action, fut) = handle_stop_action(&mut recv);
        match stop_action {
            OnStop::Sleep => {
                if let Some(fut) = fut {
                    let _ = thread_shared.status.0.send(Status::Stopped);
                    fut.await.unwrap();
                    continue;
                }
            }
            OnStop::Exit => {
                let _ = thread_shared.status.0.send(Status::Shutdown);
                break;
            }
            OnStop::Restart => {
                let _ = thread_shared.status.0.send(Status::Running);
            }
        }
        match run_main(thread_shared).await {
            Ok(Ok(NoOutput)) => (), // restart
            Ok(Err(e)) => {
                #[cfg(feature = "unstable")]
                {
                    use crate::notifications::NotificationLevel;
                    use crate::status::MainStatus;
                    let mut db = thread_shared.seed.ctx.db.handle();
                    let started = crate::db::DatabaseModel::new()
                        .package_data()
                        .idx_model(&thread_shared.seed.manifest.id)
                        .and_then(|pde| pde.installed())
                        .map::<_, MainStatus>(|i| i.status().main())
                        .get(&mut db, false)
                        .await;
                    match started.as_deref() {
                        Ok(Some(MainStatus::Running { .. })) => {
                            let res = thread_shared.seed.ctx.notification_manager
                                .notify(
                                    &mut db,
                                    Some(thread_shared.seed.manifest.id.clone()),
                                    NotificationLevel::Warning,
                                    String::from("Service Crashed"),
                                    format!("The service {} has crashed with the following exit code: {}\nDetails: {}", thread_shared.seed.manifest.id.clone(), e.0, e.1),
                                    (),
                                    Some(3600) // 1 hour
                                )
                                .await;
                            if let Err(e) = res {
                                tracing::error!("Failed to issue notification: {}", e);
                                tracing::debug!("{:?}", e);
                            }
                        }
                        _ => {
                            tracing::error!("service just started. not issuing crash notification")
                        }
                    }
                }
                tracing::error!("service crashed: {}: {}", e.0, e.1);
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Err(e) => {
                tracing::error!("failed to start service: {}", e);
                tracing::debug!("{:?}", e);
            }
        }
    }
}

pub struct PersistentContainer {
    _running_docker: NonDetachingJoinHandle<()>,
    rpc_client: Receiver<Arc<UnixRpcClient>>,
}

impl PersistentContainer {
    #[instrument(skip(seed))]
    async fn init(seed: &Arc<ManagerSeed>) -> Result<ManagerPersistantContainer, Error> {
        Ok(if let Some(containers) = &seed.manifest.containers {
            let (running_docker, rpc_client) =
                spawn_persistent_container(seed.clone(), containers.main.clone()).await?;
            Some(Arc::new(Self {
                _running_docker: running_docker,
                rpc_client,
            }))
        } else {
            None
        })
    }
}

fn spawn_persistent_container(
    seed: Arc<ManagerSeed>,
    container: DockerContainer,
) -> Result<(NonDetachingJoinHandle<()>, Receiver<Arc<UnixRpcClient>>), Error> {
    let (send_inserter, inserter) = oneshot::channel();
    Ok((
        tokio::task::spawn(async move {
            let mut inserter_send: Option<Sender<Arc<UnixRpcClient>>> = None;
            let mut send_inserter: Option<oneshot::Sender<Receiver<Arc<UnixRpcClient>>>> = Some(send_inserter);
            loop {
                if let Err(e) = async {
                    let interfaces = main_interfaces(&*seed)?;
                    let generated_certificate = generate_certificate(&*seed, &interfaces).await?;
                    let (mut runtime, inserter) =
                        long_running_docker(&seed, &container).await?;

                    let ip = match get_long_running_ip(&*seed, &mut runtime).await {
                        GetRunningIp::Ip(x) => x,
                        GetRunningIp::Error(e) => return Err(e),
                        GetRunningIp::EarlyExit(e) => {
                            tracing::error!("Early Exit");
                            tracing::debug!("{:?}", e);
                            return Ok(());
                        }
                    };
                    add_network_for_main(&*seed, ip, interfaces, generated_certificate).await?;

                    if let Some(inserter_send) = inserter_send.as_mut() {
                        let _ = inserter_send.send(Arc::new(inserter));
                    } else {
                        let (s, r) = channel(Arc::new(inserter));
                        inserter_send = Some(s);
                        if let Some(send_inserter) = send_inserter.take() {
                            let _ = send_inserter.send(r);
                        }
                    }

                    let res = tokio::select! {
                        a = runtime.running_output => a.map_err(|_| Error::new(eyre!("Manager runtime panicked!"), crate::ErrorKind::Docker)).map(|_| ()),
                    };

                    remove_network_for_main(&*seed, ip).await?;

                    res
                }.await {
                    tracing::error!("Error in persistent container: {}", e);
                    tracing::debug!("{:?}", e);
                } else {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .into(),
        inserter.await.map_err(|_| Error::new(eyre!("Container handle dropped before inserter sent"), crate::ErrorKind::Unknown))?,
    ))
}

async fn long_running_docker(
    seed: &ManagerSeed,
    container: &DockerContainer,
) -> Result<(LongRunning, UnixRpcClient), Error> {
    container
        .long_running_execute(
            &seed.ctx,
            &seed.manifest.id,
            &seed.manifest.version,
            &seed.manifest.volumes,
        )
        .await
}

async fn remove_network_for_main(seed: &ManagerSeed, ip: std::net::Ipv4Addr) -> Result<(), Error> {
    seed.ctx
        .net_controller
        .remove(
            &seed.manifest.id,
            ip,
            seed.manifest.interfaces.0.keys().cloned(),
        )
        .await?;
    Ok(())
}

fn fetch_starting_to_running(state: &Arc<ManagerSharedState>) {
    let _ = state.status.0.send_modify(|x| {
        if *x == Status::Starting {
            *x = Status::Running;
        }
    });
}

async fn main_health_check_daemon(seed: Arc<ManagerSeed>) {
    tokio::time::sleep(Duration::from_secs(HEALTH_CHECK_GRACE_PERIOD_SECONDS)).await;
    loop {
        let mut db = seed.ctx.db.handle();
        if let Err(e) = health::check(&seed.ctx, &mut db, &seed.manifest.id).await {
            tracing::error!(
                "Failed to run health check for {}: {}",
                &state.seed.manifest.id,
                e
            );
            tracing::debug!("{:?}", e);
        }
        tokio::time::sleep(Duration::from_secs(HEALTH_CHECK_COOLDOWN_SECONDS)).await;
    }
}

fn set_commit_health_true(state: &Arc<ManagerSharedState>) {
    state
        .commit_health_check_results
        .store(true, Ordering::SeqCst);
}

async fn add_network_for_main(
    seed: &ManagerSeed,
    ip: std::net::Ipv4Addr,
    interfaces: Vec<(
        InterfaceId,
        &crate::net::interface::Interface,
        TorSecretKeyV3,
    )>,
    generated_certificate: GeneratedCertificateMountPoint,
) -> Result<(), Error> {
    seed.ctx
        .net_controller
        .add(&seed.manifest.id, ip, interfaces, generated_certificate)
        .await?;
    Ok(())
}

enum GetRunningIp {
    Ip(Ipv4Addr),
    Error(Error),
    EarlyExit(Result<NoOutput, (i32, String)>),
}

type RuntimeOfCommand = NonDetachingJoinHandle<Result<Result<NoOutput, (i32, String)>, Error>>;

async fn get_running_ip(seed: &ManagerSeed, mut runtime: &mut RuntimeOfCommand) -> GetRunningIp {
    loop {
        match container_inspect(seed).await {
            Ok(res) => {
                match res
                    .network_settings
                    .and_then(|ns| ns.networks)
                    .and_then(|mut n| n.remove("start9"))
                    .and_then(|es| es.ip_address)
                    .filter(|ip| !ip.is_empty())
                    .map(|ip| ip.parse())
                    .transpose()
                {
                    Ok(Some(ip_addr)) => return GetRunningIp::Ip(ip_addr),
                    Ok(None) => (),
                    Err(e) => return GetRunningIp::Error(e.into()),
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, // NOT FOUND
                ..
            }) => (),
            Err(e) => return GetRunningIp::Error(e.into()),
        }
        if let Poll::Ready(res) = futures::poll!(&mut runtime) {
            match res {
                Ok(Ok(response)) => return GetRunningIp::EarlyExit(response),
                Err(e) => {
                    return GetRunningIp::Error(Error::new(
                        match e.try_into_panic() {
                            Ok(e) => {
                                eyre!(
                                    "Manager runtime panicked: {}",
                                    e.downcast_ref::<&'static str>().unwrap_or(&"UNKNOWN")
                                )
                            }
                            _ => eyre!("Manager runtime cancelled!"),
                        },
                        crate::ErrorKind::Docker,
                    ))
                }
                Ok(Err(e)) => {
                    return GetRunningIp::Error(Error::new(
                        eyre!("Manager runtime returned error: {}", e),
                        crate::ErrorKind::Docker,
                    ))
                }
            }
        }
    }
}

async fn get_long_running_ip(seed: &ManagerSeed, runtime: &mut LongRunning) -> GetRunningIp {
    loop {
        match container_inspect(seed).await {
            Ok(res) => {
                match res
                    .network_settings
                    .and_then(|ns| ns.networks)
                    .and_then(|mut n| n.remove("start9"))
                    .and_then(|es| es.ip_address)
                    .filter(|ip| !ip.is_empty())
                    .map(|ip| ip.parse())
                    .transpose()
                {
                    Ok(Some(ip_addr)) => return GetRunningIp::Ip(ip_addr),
                    Ok(None) => (),
                    Err(e) => return GetRunningIp::Error(e.into()),
                }
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, // NOT FOUND
                ..
            }) => (),
            Err(e) => return GetRunningIp::Error(e.into()),
        }
        if let Poll::Ready(res) = futures::poll!(&mut runtime.running_output) {
            match res {
                Ok(_) => return GetRunningIp::EarlyExit(Ok(NoOutput)),
                Err(_e) => {
                    return GetRunningIp::Error(Error::new(
                        eyre!("Manager runtime panicked!"),
                        crate::ErrorKind::Docker,
                    ))
                }
            }
        }
    }
}

async fn container_inspect(
    seed: &ManagerSeed,
) -> Result<bollard::models::ContainerInspectResponse, bollard::errors::Error> {
    seed.ctx
        .docker
        .inspect_container(&seed.container_name, None)
        .await
}

async fn generate_certificate(
    seed: &ManagerSeed,
    interfaces: &Vec<(
        InterfaceId,
        &crate::net::interface::Interface,
        TorSecretKeyV3,
    )>,
) -> Result<GeneratedCertificateMountPoint, Error> {
    seed.ctx
        .net_controller
        .generate_certificate_mountpoint(&seed.manifest.id, interfaces)
        .await
}

fn main_interfaces(
    seed: &ManagerSeed,
) -> Result<
    Vec<(
        InterfaceId,
        &crate::net::interface::Interface,
        TorSecretKeyV3,
    )>,
    Error,
> {
    seed.manifest
        .interfaces
        .0
        .iter()
        .map(|(id, info)| {
            Ok((
                id.clone(),
                info,
                seed.tor_keys
                    .get(id)
                    .ok_or_else(|| {
                        Error::new(eyre!("interface {} missing key", id), crate::ErrorKind::Tor)
                    })?
                    .clone(),
            ))
        })
        .collect::<Result<Vec<_>, Error>>()
}

async fn wait_for_status(shared: &ManagerSharedState, status: Status) {
    let mut recv = shared.status.0.subscribe();
    while {
        let s = *recv.borrow();
        s != status
    } {
        if recv.changed().await.is_ok() {
            break;
        }
    }
}

fn sigterm_timeout(manifest: &Manifest) -> Option<Duration> {
    if let PackageProcedure::Docker(d) = &manifest.main {
        d.sigterm_timeout.map(|d| *d)
    } else if let Some(c) = &manifest.containers {
        c.main.sigterm_timeout.map(|d| *d)
    } else {
        None
    }
}

#[instrument(skip(shared))]
async fn stop(shared: &ManagerSharedState) -> Result<(), Error> {
    shared
        .commit_health_check_results
        .store(false, Ordering::SeqCst);
    shared.on_stop.send_modify(|status| {
        if matches!(*status, OnStop::Restart) {
            *status = OnStop::Sleep;
        }
    });
    if *shared.status.1.borrow() == Status::Paused {
        resume(shared).await?;
    }
    send_signal(shared, &Signal::SIGTERM).await?;
    let _ = tokio::time::timeout(
        sigterm_timeout(&shared.seed.manifest).unwrap_or(Duration::from_secs(30)),
        wait_for_status(shared, Status::Stopped),
    )
    .await;
    shared.killer.notify_waiters();

    Ok(())
}

#[instrument(skip(shared))]
async fn start(shared: &ManagerSharedState) -> Result<(), Error> {
    shared.on_stop.send_modify(|status| {
        if matches!(*status, OnStop::Sleep) {
            *status = OnStop::Restart;
        }
    });
    let _ = shared.status.0.send_modify(|x| {
        if *x != Status::Running {
            *x = Status::Starting
        }
    });
    Ok(())
}

#[instrument(skip(shared))]
async fn pause(shared: &ManagerSharedState) -> Result<(), Error> {
    if let Err(e) = shared
        .seed
        .ctx
        .docker
        .pause_container(&shared.seed.container_name)
        .await
    {
        tracing::error!("failed to pause container. stopping instead. {}", e);
        tracing::debug!("{:?}", e);
        return stop(shared).await;
    }
    let _ = shared.status.0.send(Status::Paused);
    Ok(())
}

#[instrument(skip(shared))]
async fn resume(shared: &ManagerSharedState) -> Result<(), Error> {
    shared
        .seed
        .ctx
        .docker
        .unpause_container(&shared.seed.container_name)
        .await?;
    let _ = shared.status.0.send(Status::Running);
    Ok(())
}

async fn send_signal(shared: &ManagerSharedState, signal: &Signal) -> Result<(), Error> {
    // stop health checks from committing their results
    shared
        .commit_health_check_results
        .store(false, Ordering::SeqCst);

    if let Some(rpc_client) = shared
        .persistent_container
        .as_ref()
        .map(|c| c.rpc_client.borrow().clone())
    {
        #[cfg(feature = "js_engine")]
        if let Err(e) = JsProcedure::default()
            .execute::<_, NoOutput>(
                &shared.seed.ctx.datadir,
                &shared.seed.manifest.id,
                &shared.seed.manifest.version,
                ProcedureName::Signal,
                &shared.seed.manifest.volumes,
                Some(SignalGroupParams {
                    gid: shared.main_gid.1.apply_ref(|g| *g.borrow()),
                    signal: *signal as u32,
                }),
                None, // TODO BLUJ
                ProcessGroupId(
                    shared
                        .next_gid
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                ),
                Some(rpc_client),
            )
            .await?
        {
            tracing::error!("Failed to send js signal: {}", e.1);
            tracing::debug!("{:?}", e);
        }
    } else {
        // send signal to container
        shared
            .seed
            .ctx
            .docker
            .kill_container(
                &shared.seed.container_name,
                Some(KillContainerOptions {
                    signal: signal.to_string(),
                }),
            )
            .await
            .or_else(|e| {
                if matches!(
                    e,
                    bollard::errors::Error::DockerResponseServerError {
                        status_code: 409, // CONFLICT
                        ..
                    } | bollard::errors::Error::DockerResponseServerError {
                        status_code: 404, // NOT FOUND
                        ..
                    }
                ) {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
    }

    Ok(())
}

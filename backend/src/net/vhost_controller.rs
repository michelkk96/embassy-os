use crate::net::embassy_service_http_server::EmbassyServiceHTTPServer;
use crate::net::proxy_controller::ProxyController;
use crate::net::ssl::SslManager;
use crate::{Error};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use futures::FutureExt;

use crate::net::{HttpClient, HttpHandler};

pub struct VHOSTController {
    pub service_servers: BTreeMap<u16, EmbassyServiceHTTPServer>,
    embassyd_addr: SocketAddr,
}

impl VHOSTController {
    pub fn init(embassyd_addr: SocketAddr) -> Self {
        Self {
            embassyd_addr,
            service_servers: BTreeMap::new(),
        }
    }

    pub async fn add_docker_svc_handle(
        &mut self,
        external_svc_port: u16,
        fqdn: String,
        proxy_addr: SocketAddr,
    ) -> Result<(), Error> {
        let svc_handler: HttpHandler = Arc::new(move |mut req| {
            async move {
                let client = HttpClient::new();

                let uri_string = format!(
                    "http://{}{}",
                    proxy_addr,
                    req.uri()
                        .path_and_query()
                        .map(|x| x.as_str())
                        .unwrap_or("/")
                );

                let uri = uri_string.parse().unwrap();
                *req.uri_mut() = uri;

                // Ok::<_, HyperError>(Response::new(Body::empty()))
                return ProxyController::proxy(client, req).await;
            }
            .boxed()
        });

        self.add_server_or_handle(external_svc_port, fqdn, svc_handler)
            .await?;
        Ok(())
    }

    pub async fn add_server_or_handle(
        &mut self,
        external_svc_port: u16,
        fqdn: String,
        svc_handler: HttpHandler,
    ) -> Result<(), Error> {
        if let Some(server) = self.service_servers.get_mut(&external_svc_port) {
            server.add_svc_mapping(fqdn, svc_handler).await;
        } else {
            let mut new_service_server =
                EmbassyServiceHTTPServer::new(self.embassyd_addr.ip(), external_svc_port).await?;
            new_service_server.add_svc_mapping(fqdn, svc_handler).await;

            self.service_servers
                .insert(external_svc_port, new_service_server);
        }

        Ok(())
    }
}
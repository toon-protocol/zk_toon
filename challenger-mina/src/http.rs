//! GraphQL over HTTP, optionally through a SOCKS proxy.
use std::time::Duration;

use serde_json::Value;

use crate::graphql::{Endpoint, Graphql};

/// The two GraphQL endpoints and how to reach them.
#[derive(Clone, Debug)]
pub struct Endpoints {
    /// The Mina daemon's GraphQL URL.
    pub mina: String,
    /// The archive node API's GraphQL URL.
    pub archive: String,
    /// Opt in to reaching both through this SOCKS5 proxy (`host:port`). The proxy resolves the
    /// endpoints' host names, and there is no direct fallback: if the proxy can't be reached, nothing is.
    pub socks5: Option<String>,
    /// How long one request may take.
    pub timeout: Duration,
}

/// [`Graphql`] over HTTP(S).
pub struct HttpGraphql {
    endpoints: Endpoints,
    agent: ureq::Agent,
}

impl HttpGraphql {
    pub fn new(endpoints: Endpoints) -> Result<Self, String> {
        let mut agent = ureq::AgentBuilder::new().timeout(endpoints.timeout);
        if let Some(proxy) = &endpoints.socks5 {
            // `socks5://` in ureq hands the host name to the proxy, which resolves it.
            agent = agent.proxy(ureq::Proxy::new(format!("socks5://{proxy}")).map_err(|e| format!("socks proxy: {e}"))?);
        }
        Ok(HttpGraphql { agent: agent.build(), endpoints })
    }
}

impl Graphql for HttpGraphql {
    fn post(&self, endpoint: Endpoint, request: &Value) -> Result<Value, String> {
        let url = match endpoint {
            Endpoint::Mina => &self.endpoints.mina,
            Endpoint::Archive => &self.endpoints.archive,
        };
        let body = request.to_string();
        let response = match self.agent.post(url).set("Content-Type", "application/json").send_string(&body) {
            Ok(r) => r,
            // GraphQL servers answer errors with a JSON body too.
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => return Err(e.to_string()),
        };
        let text = response.into_string().map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| format!("not JSON: {e}"))
    }
}

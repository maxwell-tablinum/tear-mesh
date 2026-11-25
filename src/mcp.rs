//! `tearmesh mcp`: the stdio MCP server a harness loads, serving the conversation and agent tools
//! (`talk`). It runs as the session's OS user, so the daemon knows the session's boundary from the
//! socket. It holds its mailbox while it runs.
//! `tearmesh mcp --remote <machine>/<server>` is instead a shim for one server another machine
//! offers: it looks like any stdio MCP server, and the daemons carry and filter the session.

use anyhow::Result;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData, ServerHandler, ServiceExt};

use crate::ipc::{Client, Request};
use crate::talk::{Door, Talk};

#[derive(Clone)]
pub struct Server {
    talk: Talk,
}

impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("tearmesh", env!("CARGO_PKG_VERSION")))
            .with_instructions(self.talk.instructions())
    }

    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(self.talk.tools()))
    }

    async fn call_tool(
        &self,
        req: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let r = self.talk.call(&req.name, req.arguments.unwrap_or_default()).await;
        Ok(crate::talk::to_result(r).into())
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.talk.tools().into_iter().find(|t| t.name == name)
    }
}

/// A shim for `server` on `machine`: stdio in and out, carried by the daemons.
pub async fn remote(target: &str) -> Result<()> {
    let (machine, server) = target
        .split_once('/')
        .filter(|(m, s)| crate::valid_name(m) && crate::valid_name(s))
        .ok_or_else(|| anyhow::anyhow!("use --remote <machine>/<server>"))?;
    let mut c = Client::connect(&crate::ipc::socket_path()).await?;
    c.call(&Request::Remote {
        machine: machine.into(),
        server: server.into(),
    })
    .await?;
    let (r, w) = c.into_raw();
    crate::shell::splice(tokio::io::stdin(), tokio::io::stdout(), r, w).await
}

pub async fn run() -> Result<()> {
    let talk = Talk::new(Door {
        mailbox: None,
        trust: None,
        hold: true,
        agent_tools: true,
    });
    // Opens the session now, so the mailbox is held and the instructions carry the address. With
    // no daemon the server still starts; every tool then says why it can't work.
    let _ = talk.address().await;
    Server { talk }
        .serve(rmcp::transport::stdio())
        .await?
        .waiting()
        .await?;
    Ok(())
}

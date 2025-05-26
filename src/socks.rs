//! A simple Socks proxy implementation
//!
//! The goal of this module isn't to have a Socks proxy that goes trough Tor, like Arti or c-tor
//! do.
//! Instead, this is a very simple Socks proxy which will be stuck inside the network namespace.
//! Software configured to use tor, and software which are RFC7686 compliant can use this proxy
//! instead of direct tcp connections to onion0. Trying to run this module outside of a network
//! namespace is a very bad idea as it will give a false sens of security.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;

use tor_socksproto::{Handshake, SocksAddr, SocksCmd, SocksRequest};

use log::warn;

// the name is volontarily annoying because i want people to know this may not be what they think
// it is.
pub async fn run_naive_proxy_from_inside_a_network_namespace(
    bind_addr: SocketAddr,
    notify: Arc<Notify>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("failed to bind Socks proxy")?;

    let mut join_set = JoinSet::new();

    tokio::select! {
        _ = async {
            while let Ok((conn, _addr)) = listener.accept().await {
            join_set.spawn(handle_single_conn(conn));
        }} => {},
        _ = notify.notified() => {},
    };
    Ok(())
}

async fn handle_single_conn(mut socks_stream: TcpStream) -> anyhow::Result<()> {
    let mut handshake = tor_socksproto::SocksProxyHandshake::new();

    let mut inbuf = tor_socksproto::Buffer::new();
    let request = loop {
        use tor_socksproto::NextStep as NS;

        let step = handshake.step(&mut inbuf)?;

        match step {
            NS::Recv(mut recv) => {
                let n = socks_stream
                    .read(recv.buf())
                    .await
                    .context("Error while reading SOCKS handshake")?;
                recv.note_received(n)?;
            }
            NS::Send(data) => write_all_and_flush(&mut socks_stream, &data).await?,
            NS::Finished(fin) => break fin.into_output_forbid_pipelining()?,
        }
    };

    match request.command() {
        SocksCmd::CONNECT => {
            let port = request.port();
            let addr = match request.addr() {
                SocksAddr::Hostname(hostname) => {
                    let lookup = tokio::net::lookup_host((hostname.as_ref(), port)).await;
                    let mut lookup = match lookup {
                        Ok(lookup) => lookup,
                        Err(e) => return reply_error(&mut socks_stream, &request, e).await,
                    };
                    match lookup.next() {
                        Some(ip) => ip,
                        None => {
                            return reply_error(
                                &mut socks_stream,
                                &request,
                                anyhow!("failed lookup"),
                            )
                            .await
                        }
                    }
                }
                SocksAddr::Ip(ip) => SocketAddr::new(*ip, port),
            };
            // The SOCKS request wants us to connect to a given address.
            // So, launch a connection over Tor.
            let upstream_stream = TcpStream::connect(addr).await;
            let mut upstream_stream = match upstream_stream {
                Ok(s) => s,
                Err(e) => return reply_error(&mut socks_stream, &request, e).await,
            };

            // Send back a SOCKS response, telling the client that it
            // successfully connected.
            let reply = request
                .reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .context("Encoding socks reply")?;
            write_all_and_flush(&mut socks_stream, &reply[..]).await?;

            let _ = tokio::io::copy_bidirectional(&mut socks_stream, &mut upstream_stream).await;
            let _ = socks_stream.shutdown().await;
            let _ = upstream_stream.shutdown().await;
        }
        _ => {
            // we could support RESOLVE/RESOLVE_PTR tor extensions
            warn!("Dropping request; {:?} is unsupported", request.command());
            let reply = request
                .reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None)
                .context("Encoding socks reply")?;
            write_all_and_close(&mut socks_stream, &reply[..]).await?;
        }
    }
    Ok(())
}

/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing SOCKS stream")
}

/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .shutdown()
        .await
        .context("Error while closing SOCKS stream")
}

/// Returns the error provided in parameter
async fn reply_error<W, E>(writer: &mut W, request: &SocksRequest, error: E) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
    E: Into<anyhow::Error>,
{
    let reply = request
        .reply(tor_socksproto::SocksStatus::GENERAL_FAILURE, None)
        .context("Encoding socks reply")?;
    // if writing back the error fail, still return the original error
    let _ = write_all_and_close(writer, &reply[..]).await;

    Err(anyhow!(error))
}

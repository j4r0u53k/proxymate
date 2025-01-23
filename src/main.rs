use std::fs::File;
use std::fmt::{Debug, Display};
use std::io::BufReader;
use std::time::Duration;
use std::sync::Arc;
use async_std::task;
use async_std::net::{TcpListener, TcpStream, ToSocketAddrs};
use async_std::io::ErrorKind;
use async_std::path::{Path, PathBuf};
use futures::{AsyncReadExt, AsyncRead, AsyncWrite, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use structopt::StructOpt;
use rustls::{ServerConfig, ClientConfig};
use log::*;

#[derive(Debug, StructOpt)]
struct CliOptions {
    #[structopt(long, help = "Use WebSockets for the server")]
    server_ws: bool,

    #[structopt(long, help = "Use TLS for the server")]
    server_tls: bool,

    #[structopt(short = "k", long, help = "Server private key file in PEM format")]
    server_key: Option<PathBuf>,

    #[structopt(short = "c", long, help = "Server certificates file(s) in PEM format")]
    server_certs: Option<Vec<PathBuf>>,

    #[structopt(long, help = "CA Certificates file in PEM format")]
    ca_certs: Option<PathBuf>,

    #[structopt(short = "l", long, help = "Server listen address:port")]
    listen_addr: String,

    #[structopt(long, help = "Use WebSockets for connection to the target")]
    target_ws: bool,

    #[structopt(long, help = "Use TLS for connection to the target")]
    target_tls: bool,

    #[structopt(short = "t", long, help = "Target address:port")]
    target_addr: String,

    #[structopt(long, default_value = "5", help = "Timeout in seconds for establishing connection and handshakes")]
    handshake_timeout: u16,
}

struct ServerOptions {
    tls_config: Option<ServerConfig>,
    ws: bool,
}

struct TargetOptions<T: ToSocketAddrs + Display> {
    address: T,
    domain: String,
    tls_config: Option<ClientConfig>,
    ws: bool,
}


trait AsyncRW: AsyncRead + AsyncWrite {}
impl<T> AsyncRW for T where T: AsyncRead + AsyncWrite {}

type AsyncRWBox = Box<dyn AsyncRW + Unpin + Send>;

fn load_certs<'b>(certs_file: &Path) -> Result<Vec<CertificateDer<'b>>, std::io::Error> {
    let mut reader = BufReader::new(File::open(certs_file)?);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_keys<'b>(key_file: &Path) -> Result<Vec<PrivateKeyDer<'b>>, std::io::Error> {
    let keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(key_file)?))
        .map(|key|
            key.map(PrivateKeyDer::Pkcs8)
        )
        .collect::<Result<Vec<_>,_>>()?;

    if !keys.is_empty() {
        Ok(keys)
    } else {
        // If no keys in PKCS#8 format were found, try it once again for PKCS#1 format
        rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(key_file)?))
        .map(|key|
            key.map(PrivateKeyDer::Pkcs1)
        )
        .collect::<Result<Vec<_>,_>>()
    }
}

fn load_server_config(options: &CliOptions) -> Result<ServerConfig, std::io::Error> {
    let mut certs: Vec<CertificateDer> = Vec::new();
    if let Some(ref cert_files) = options.server_certs {
        for file in cert_files {
            certs.append(&mut load_certs(file)
                .map_err(|err| {
                    error!("Cannot load server certificates from {:?}, reason: {}", file, err);
                    err
                })?);
        }
    }

    let mut keys = load_keys(&options.server_key
        .clone()
        .ok_or_else(|| {
            error!("No server key provided");
            std::io::Error::from(std::io::ErrorKind::InvalidInput)
        })?)
        .map_err(|e|{error!("Cannot load server key, reason: {}", e); e})?;

    info!("Loaded {} certificates, {} keys", certs.len(), keys.len());

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certs,
            keys.pop().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key"))?
        )
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;

    Ok(config)
}

fn load_server_options(cli_options: &CliOptions) -> Result<ServerOptions, std::io::Error> {
    Ok(ServerOptions {
        tls_config: if cli_options.server_tls {
            Some(load_server_config(cli_options)?)
        } else {
            None
        },
        ws: cli_options.server_ws
    })
}

fn load_target_options(cli_options: &CliOptions) -> Result<TargetOptions<String>, std::io::Error> {
    let target_domain = cli_options.target_addr.split(':').next()
        .ok_or_else(|| {
            error!("Invalid target address format");
            std::io::Error::from(std::io::ErrorKind::InvalidInput)})?;

    Ok(TargetOptions {
        address: cli_options.target_addr.clone(),
        domain: target_domain.to_string(),
        tls_config: if cli_options.target_tls {
            Some(load_client_config(cli_options)?)
        } else {
            None
        },
        ws: cli_options.target_ws
    })
}

fn load_client_config(options: &CliOptions) -> Result<ClientConfig, std::io::Error> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    if let Some(ca_certs) = &options.ca_certs {
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(ca_certs)?))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                error!("Can't add root certificate");
                std::io::Error::from(ErrorKind::InvalidInput)
            })?;
        let (added, ignored) = root_cert_store.add_parsable_certificates(certs);
        info!("CA certificates added: {}, ignored: {}", added, ignored);
    };

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    config.enable_sni = false;

    Ok(config)
}

async fn server_handshake(stream: TcpStream, options: Arc<ServerOptions>, timeout: &Duration) -> Result<AsyncRWBox, std::io::Error> {
    let peer_addr = stream.peer_addr()?;

    let stream: AsyncRWBox = if let Some(config) = &options.tls_config {
        info!("Establishing TLS server handshake with {} ...", &peer_addr);

        let tls_stream = async_std::io::timeout(*timeout, async {
            async_tls::TlsAcceptor::from(config.clone()).accept(stream).await
        }).await.map_err(|err| {
            error!("Can't establish TLS server handshake with client {}, error: {}", peer_addr, err);
            err
        })?;

        info!("TLS server handshake with client {} complete", &peer_addr);
        Box::new(tls_stream)
    }
    else {
        Box::new(stream)
    };

    if options.ws {
        info!("Establishing WebSockets server handshake with client {} ...", &peer_addr);

        let ws_stream = async_std::io::timeout(*timeout, async {
            async_tungstenite::accept_async(stream).await
                .map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused,err)
                })
        }).await.map_err(|err| {
            error!("Can't establish WebSockets server handshake with client {}, error: {}", peer_addr, err);
            err
        })?;

        info!("WebSockets server handshake with client {} complete", &peer_addr);
        Ok(Box::new(ws_stream_tungstenite::WsStream::new(ws_stream)))
    }
    else {
        Ok(stream)
    }
}

fn ws_request_url<T: Display>(addr: &T, is_tls: bool) -> String {
    format!("{}://{}", if is_tls { "wss" } else { "ws" }, addr)
}

async fn target_handshake<T, U>(options: Arc<TargetOptions<T>>, client_addr: &U, timeout: &Duration) -> Result<AsyncRWBox, std::io::Error>
    where T: ToSocketAddrs + Display,
          U: Display,
{
    let target_addr = &options.address;
    info!("{} Connecting to the target ({}) ...", client_addr, target_addr);

    let target_stream = async_std::io::timeout(*timeout, async {
        TcpStream::connect(target_addr).await
    }).await.map_err(|err| {
        error!("{} Can't connect to the target, error: {}", client_addr, err);
        err
    })?;

    info!("{} TCP connection to the target complete", client_addr);

    let target_stream: AsyncRWBox = if let Some(ref tls_config) = options.tls_config {
        let tls_stream = async_std::io::timeout(*timeout, async {
            async_tls::TlsConnector::from(tls_config.clone())
                .connect(&options.domain, target_stream).await
        }).await.map_err(|err| {
            error!("{} TLS handshake with the target error: {}", client_addr, err);
            err
        })?;

        info!("{} TLS handshake with the target complete", client_addr);
        Box::new(tls_stream)
    } else {
        Box::new(target_stream)
    };

    if options.ws {
        let (ws_stream, _) = async_std::io::timeout(*timeout, async {
            async_tungstenite::client_async(ws_request_url(&target_addr.to_string(), options.tls_config.is_some()), target_stream).await
                .map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused,err)
                })
        }).await.map_err(|err| {
            error!("{} WebSockets handshake with the target error: {}", client_addr, err);
            err
        })?;

        info!("{} WebSockets handshake with the target established", client_addr);
        Ok(Box::new(ws_stream_tungstenite::WsStream::new(ws_stream)))
    } else {
        Ok(target_stream)
    }
}

async fn handle_connection<T>(front_stream: TcpStream,
                              server_options: Arc<ServerOptions>,
                              target_options: Arc<TargetOptions<T>>,
                              handshake_timeout: Duration) -> Result<(), std::io::Error>
    where T:  ToSocketAddrs + Display
{
    let client_addr = front_stream.peer_addr()?;

    let front_stream = server_handshake(front_stream, server_options, &handshake_timeout).await?;
    let target_stream = target_handshake(target_options.clone(), &client_addr, &handshake_timeout).await?;

    info!("{} Connection to the target established", &client_addr);
    do_transfer(front_stream, target_stream).await;
    info!("{} Connection terminated", &client_addr);

    Ok(())
}

async fn do_transfer(stream_a: AsyncRWBox, stream_b: AsyncRWBox) {
    let (mut reader_a, mut writer_a) = stream_a.split();
    let (mut reader_b, mut writer_b) = stream_b.split();

    futures::future::select(
        std::pin::pin!(async_std::io::copy(&mut reader_a, &mut writer_b)),
        std::pin::pin!(async_std::io::copy(&mut reader_b, &mut writer_a))
        ).await;
}

async fn run_proxy(listen_addr: String,
                    server_options: Arc<ServerOptions>,
                    target_options: Arc<TargetOptions<String>>,
                    handshake_timeout: Duration) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    let mut incoming = listener.incoming();

    info!("Server listening at {}", listener.local_addr()?);

    while let Some(stream) = incoming.next().await {
        let stream = stream?;

        let server_options = server_options.clone();
        let target_options = target_options.clone();

        task::spawn(async move {
            let peer_addr = stream.peer_addr().unwrap();
            info!("New connection from {}", &peer_addr);

            if let Err(err) = handle_connection(stream, server_options, target_options, handshake_timeout).await {
                error!("{} Error handling connection: {}", &peer_addr, err);
            }
            info!("{} Client disconnected", &peer_addr);
        });
    }

    Ok(())
}

const PROGRAM_NAME: &str = env!("CARGO_PKG_NAME");
const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or("info"))
        .format_timestamp_millis()
        .format_target(false)
        .init();

    info!("=== {} v{} ===", PROGRAM_NAME, PROGRAM_VERSION);

    let options: CliOptions = CliOptions::from_args();
    info!("Run with options: {:?}", options);

    let server_options = Arc::new(load_server_options(&options)?);
    let target_options = Arc::new(load_target_options(&options)?);
    let handshake_timeout = Duration::from_secs(options.handshake_timeout as u64);

    task::block_on(run_proxy(options.listen_addr, server_options, target_options, handshake_timeout))
}

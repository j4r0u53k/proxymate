use std::fs::File;
use std::fmt::{Debug, Display};
use std::io::{BufReader, Seek};
use std::time::Duration;
use std::sync::Arc;
use async_std::task;
use async_std::net::{TcpListener, TcpStream, ToSocketAddrs};
use async_std::io::ErrorKind;
use async_std::path::{Path, PathBuf};
use futures::{FutureExt, pin_mut, AsyncReadExt, AsyncRead, AsyncWrite, StreamExt};
use structopt::StructOpt;
use rustls_pemfile;
use rustls::{Certificate, NoClientAuth, PrivateKey, ServerConfig, ClientConfig};
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

fn load_certs(certs_file: &Path) -> Result<Vec<Certificate>, std::io::Error> {
    let mut reader = BufReader::new(File::open(certs_file)?);

    rustls_pemfile::certs(&mut reader)
        .map(|certs|
            certs.into_iter().map(|vec| Certificate(vec)).collect())
}

fn load_keys(key_file: &Path) -> Result<Vec<PrivateKey>, std::io::Error> {
    let mut reader = BufReader::new(File::open(key_file)?);

    let keys: Vec<PrivateKey> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .map(|keys|
            keys.into_iter()
                .map(|key| PrivateKey(key))
                .collect())?;

    if keys.len() > 0 {
        Ok(keys)
    } else {
        // If no keys in PKCS#8 format were found, try it once again for PKCS#1 format
        reader.rewind()?;
        rustls_pemfile::rsa_private_keys(&mut reader)
            .map(|keys|
                keys.into_iter()
                    .map(|key| PrivateKey(key))
                    .collect())
    }
}

fn load_server_config(options: &CliOptions) -> Result<ServerConfig, std::io::Error> {
    let mut certs: Vec<Certificate> = Vec::new();
    if let Some(ref cert_files) = options.server_certs {
        for file in cert_files {
            certs.append(&mut load_certs(file)
                .map_err(|err| {
                    error!("Cannot load server certificates from {:?}, reason: {}", file, err);
                    err
                })?);
        }
    }

    let keys = load_keys(&options.server_key
        .clone()
        .ok_or_else(|| {
            error!("No server key provided");
            std::io::Error::from(std::io::ErrorKind::InvalidInput)
        })?)
        .map_err(|e|{error!("Cannot load server key, reason: {}", e); e})?;

    info!("Loaded {} certificates, {} keys", certs.len(), keys.len());

    let mut config = ServerConfig::new(NoClientAuth::new());
    config.set_single_cert(certs,
                           keys.first()
                               .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key"))?
                               .clone())
        .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;

    Ok(config)
}

fn load_client_config(options: &CliOptions) -> Result<ClientConfig, std::io::Error> {
    let mut config = ClientConfig::new();
    config.enable_sni = false;

    if let Some(ca_certs) = &options.ca_certs {
        let (added, _) = config.root_store
            .add_pem_file(&mut BufReader::new(File::open(ca_certs)?))
            .or_else(|_| {
                error!("Can't add root certificate");
                Err(std::io::Error::from(ErrorKind::InvalidInput))
            })?;
        info!("Added {} CA certificates", added);
    }

    Ok(config)
}

async fn server_handshake(stream: TcpStream, options: Arc<ServerOptions>, timeout: &Duration) -> Result<AsyncRWBox, std::io::Error> {
    let peer_addr = stream.peer_addr()?;

    let stream: AsyncRWBox = if let Some(ref config) = options.tls_config {
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

    let stream = if options.ws {
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
        Box::new(ws_stream_tungstenite::WsStream::new(ws_stream))
    }
    else {
        stream
    };

    Ok(stream)
}

fn ws_request_url<T: Display>(addr: &T, is_tls: bool) -> String {
    format!("{}://{}", if is_tls { "wss" } else { "ws" }, addr)
}

async fn target_handshake<T, U>(options: Arc<TargetOptions<T>>, client_addr: &U, timeout: &Duration) -> Result<AsyncRWBox, std::io::Error>
    where T: ToSocketAddrs + Display,
          U: Display,
{
    let ref target_addr = options.address;
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

    let target_stream = if options.ws {
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
        Box::new(ws_stream_tungstenite::WsStream::new(ws_stream))
    } else {
        target_stream
    };

    Ok(target_stream)
}

async fn handle_connection<T>(front_stream: TcpStream,
                              server_options: Arc<ServerOptions>,
                              target_options: Arc<TargetOptions<T>>,
                              handshake_timeout: &Duration) -> Result<(), std::io::Error>
    where T:  ToSocketAddrs + Display
{
    let client_addr = front_stream.peer_addr()?;

    let front_stream = server_handshake(front_stream, server_options, handshake_timeout).await?;
    let target_stream = target_handshake(target_options.clone(), &client_addr, handshake_timeout).await?;

    info!("{} Connection to the target established", &client_addr);
    do_transfer(front_stream, target_stream).await;
    info!("{} Connection terminated", &client_addr);

    Ok(())
}

async fn do_transfer(stream_a: AsyncRWBox, stream_b: AsyncRWBox) {
    let (mut reader_a, mut writer_a) = stream_a.split();
    let (mut reader_b, mut writer_b) = stream_b.split();

    let a_to_b = async_std::io::copy(&mut reader_a, &mut writer_b).fuse();
    let b_to_a = async_std::io::copy(&mut reader_b, &mut writer_a).fuse();

    pin_mut!(a_to_b, b_to_a);
    futures::future::select(a_to_b, b_to_a).await;
}

const PROGRAM_NAME: &'static str = env!("CARGO_PKG_NAME");
const PROGRAM_VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default()
        .default_filter_or("info"))
        .format_timestamp_millis()
        .format_target(false)
        .init();

    info!("=== {} v{} ===", PROGRAM_NAME, PROGRAM_VERSION);

    let options: CliOptions = CliOptions::from_args();
    info!("Run with options: {:?}", options);

    let server_options = Arc::new(ServerOptions {
        tls_config: if options.server_tls {
            Some(load_server_config(&options)?)
        } else {
            None
        },
        ws: options.server_ws
    });

    let target_domain = options.target_addr.split(':').nth(0)
        .ok_or_else(|| {
            error!("Invalid target address format");
            std::io::Error::from(std::io::ErrorKind::InvalidInput)})?;

    let target_options = Arc::new(TargetOptions {
        address: options.target_addr.clone(),
        domain: target_domain.to_string(),
        tls_config: if options.target_tls {
            Some(load_client_config(&options)?)
        } else {
            None
        },
        ws: options.target_ws
    });

    let handshake_timeout = Duration::from_secs(options.handshake_timeout as u64);

    task::block_on(async {
        let listener = TcpListener::bind(options.listen_addr).await?;
        let mut incoming = listener.incoming();

        info!("Server listening at {}", listener.local_addr()?);

        while let Some(stream) = incoming.next().await {
            let stream = stream?;

            let server_options = server_options.clone();
            let target_options = target_options.clone();

            task::spawn(async move {
                let peer_addr = stream.peer_addr().unwrap();
                info!("New connection from {}", &peer_addr);

                if let Err(err) = handle_connection(stream, server_options, target_options, &handshake_timeout).await {
                    error!("{} Error handling connection: {}", &peer_addr, err);
                }
                info!("{} Client disconnected", &peer_addr);
            });
        }

        Ok(())
    })
}

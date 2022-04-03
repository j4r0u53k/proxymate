# proxymate

proxymate is a simple proxy written in async Rust that makes it possible to tunnel network traffic between plain TCP, TLS and/or WebSockets one to another.

The emphasized features are simplicity, reliability and scalability.

Proxymate picks [rustls] crate as the TLS library because of its quality (see [audit](https://github.com/rustls/rustls/blob/main/audit/TLS-01-report.pdf)), being written in Rust, simple, without dependency on OpenSSL. A WebSockets crate [tungstenite] is then natural choice for its compatibility with rustls.

[rustls]: https://docs.rs/rustls/0.19.1/rustls/
[tungstenite]: https://docs.rs/tungstenite/latest/tungstenite/

Both crates have their async bindings in [async_tls], [async_tungstenite] and [ws_stream_tungstenite]. With [async_std] they allow to use uniform interface of `AsyncRead` and `AsyncWrite` on various socket types.

[async_std]: https://docs.rs/async-std/latest/async_std/
[async_tls]: https://docs.rs/async-tls/latest/async_tls/
[async_tungstenite]: https://docs.rs/async-tungstenite/latest/async_tungstenite/
[ws_stream_tungstenite]: https://docs.rs/ws_stream_tungstenite/latest/ws_stream_tungstenite/

The current version does not support text messages on WebSockets due to a limitation in ws_stream_tungstenite. This could be fixed in upcoming versions if needed.

**Warning:** The current version has not yet been extensively tested nor deployed to production.


## Functional overview

```
                             +-----------+
           TCP/TLS/WS/WSS    |           |    TCP/TLS/WS/WSS
Client <====================>| proxymate |<~~~~~~~~~~~~~~~~~~~> Target (listen)
                             |           |
                             +-----------+
                             o accepts connections from clients
                             o connects to the target for each client
                             o tunnels network traffic between the client and the target
```

Program operation:

 1. proxymate is run with desired options
 1. proxymate listens at some address and port specified by `--listen-addr` parameter
 1. A client connects to proxymate
    1. The client and proxymate perform TLS handshake (if `--server-tls` present)
    1. The client and proxymate perform WebSockets handshake (if `--server-ws` present)
 1. proxymate connets to the target (specified by `--target-addr` option)
    1. proxymate and the target perform TLS handshake (if `--target-tls` present)
    1. proxymate and the target perform WebSockets handshake (if `--target-ws` present)
 1. Data is transferred between the client and target until one of the peers disconnects

## Build

Build with `cargo` is mandatory because the binary needs version information exported out of `Cargo.toml`.

```sh
proxymate $ cargo build  # append `-r` for release build
```

## Usage

```
USAGE:
    proxymate [FLAGS] [OPTIONS] --listen-addr <listen-addr> --target-addr <target-addr>

FLAGS:
    -h, --help          Prints help information
        --server-tls    Use TLS for the server
        --server-ws     Use WebSockets for the server
        --target-tls    Use TLS for connection to the target
        --target-ws     Use WebSockets for connection to the target
    -V, --version       Prints version information

OPTIONS:
        --ca-certs <ca-certs>                      CA Certificates file in PEM format
        --handshake-timeout <handshake-timeout>
            Timeout in seconds for establishing connection and handshakes [default: 5]

    -l, --listen-addr <listen-addr>                Server listen address:port
    -c, --server-certs <server-certs>...           Server certificates file(s) in PEM format
    -k, --server-key <server-key>                  Server private key file in PEM format
    -t, --target-addr <target-addr>                Target address:port
```

Detailed description of some options:

 - flags `*-tls`, `*-ws` can be arbitrarily combined.
 If `--server-tls` flag is present, then `--server-certs` and `--server-key` options become mandatory.

 - `-l, --listen-addr`

    Hostname or address of a local interface.
    - `0.0.0.0` or just `0` for all interfaces
    - `127.0.0.1` localhost only

 - `-c, --server-certs`

    List of files separated by spaces. The certificates have to form a chain of trust. The end-entity certificate must have `subjectAltName` extension as required by [rustls crate](https://docs.rs/rustls/0.19.1/rustls/struct.ServerConfig.html#method.set_single_cert). The root certificate may be present in the chain but it's useless. See [Certificates section](#certificates) for further description.

 - `-k, --server-key`

    Both PKCS#8 and PCKS#1 formats are accepted.

 - `--ca-certs`

    Client can optionally import authority certificate(s) to its own trust store. More in the [Certificates section](#certificates).

## Use cases

These are examples of possible usage of `proxymate`. In subsequent text diagrams the `{ }` means a single machine or a trusted network boundary.

1. **A TLS client wants to communicate with insecured remote server in a secure way**

   `proxymate` acts as a TLS server connecting via plain TCP to a insecured server in a trusted network:

   ```
                  (public network)
   { TLS client } <======TLS======> { proxymate <----plain TCP---> insecured server }
   ```

   run options:

   ```
   proxymate --server-tls --server-key 'server-key.pem' \
             --server-certs server-cert.pem intermediate-certs.pem \
             -l listen_addr:listen_port \
             -t target_addr:target_port
   ```

1. **A WebSockets secure (WSS) client wants to communicate with insecured remote server in a secure way**

   The same situation as in preceding use case, but `proxymate` acts as a WebSockets server on top of TLS layer.

   ```
                  (public network)
   { WSS client } <======WSS======> { proxymate <---plain TCP---> insecured server }
   ```

   run options:

   ```
   proxymate --server-ws --server-tls --server-key 'server-key.pem' \
             --server-certs server-cert.pem intermediate-certs.pem \
             -l listen_addr:listen_port \
             -t target_addr:target_port
   ```

1. **Two insecured peers want to communicate securely**

   Each party needs its own `proxymate` instance. `proxymate_A` is in plain-TCP server mode connecting to `proxymate_B` via TLS, `proxymate_B`'s role is opposite.

   ```
                                            (public network)
   { peer_A <---plain TCP---> proxymate_A } <======TLS======> { proxymate_B <---plain TCP---> peer_B }
   ```

   run options of instance **A**:

   ```
   proxymate --target-tls --ca-certs ca-cert.pem \
             -l listen_addr:listen_port \
             -t proxymate_B_addr:proxymate_B_port
   ```

   run options of instance **B**:

   ```
   proxymate --server-tls --server-key 'server-key.pem' \
             --server-certs server-cert.pem intermediate-certs.pem \
             -l listen_addr:listen_port \
             -t target_addr:target_port
   ```

1. **A WebSockets client communicating with a local TCP server**

   A typical scenario for a web client communicating with a local server. No encryption is needed since both peers are on the same machine.

   ```
   { WS client <---WS---> proxymate <---plain TCP---> local server }
   ```

   run options:

   ```
   proxymate --server-ws -l listen_addr:listen_port \
             -t target_addr:target_port
   ```

## Certificates

In order to succesfully establish a TLS session a server must present to the clients its X.509 certificate and prove it is really the server who is owner of that certificate.

A client validates the certificate presented by the server by means of chain of trust. Each certificate has a property *Subject* and *Issuer*, so the chain can be viewed as a sequence of (*Subject(n)*, *Issuer(n)*) pairs with *n* for end-entity server's certificate and *0* for a root certificate. In the chain each *Issuer(i) = Subject(i-1)* meaning that certificate *i* is issued and signed by the preceding certificate *i-1* in the chain. *Issuer(0) = Subject(0)*, so root certificates are self-signed and hence they have to be trusted apriori. It is therefore needed that a client has root certificates installed or imported to its trust store (proxymate has `--ca-certs` option for this purpose).

Server usually send a certificate chain, starting by its own end-entity certificate followed by one or more intermediate CA certificates up to the root certificate. It does not matter if the root certificate is included in the certificate chain sent by the server, because client has to have imported and trusted the root certificate before.

Server proves ownership of the end-entity certificate by possesion of corresponding private key since any data encrypted by a public key in the certificate can be decrypted only by the private key paired with that public key and any data signed by the private key can be verified by the public key.

### Creating certificates for development and testing

There are at least two certificates needed for TLS handshake:

 - Client needs to have a certificate authority (CA) root certificate imported in its trust store.

 - Server needs its end-entity certificate and private key. The certificate has to be signed either by the root certificate itself or by another intermediate certificate forming a chain of trust up to the root certificate.

X.509 certificates can be created with OpenSSL (or LibreSSL) by these steps:

1. Create a private key for CA root certificate:

   ```sh
   openssl genrsa 2048 > ca-key.pem
   ```

1. Create a CA root certificate using the private key:

   ```sh
   openssl req -new -x509 -nodes -days 365000 -key ca-key.pem -out ca-cert.pem
   ```

1. Create end-entity certificate request and private key for a server:

   ```sh
   openssl req -newkey rsa:2048 -nodes -days 365000 \
           -keyout server-key.pem -out server-req.pem
   ```

1. Create the end-entity certificate for the server with the mandatory `subjectAltName` extension and sign it by the CA:

   ```sh
   openssl x509 -req -days 365000 -set_serial 01 -in server-req.pem -out server-cert.pem \
           -CA ca-cert.pem -CAkey ca-key.pem \
           -extfile <(printf "extendedKeyUsage = serverAuth\nsubjectAltName = DNS:localhost")
   ```

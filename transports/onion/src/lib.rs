#![doc(html_logo_url = "https://libp2p.io/img/logo_small.png")]
#![doc(html_favicon_url = "https://libp2p.io/img/favicon.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! Tor based transport for libp2p. Connect through the Tor network to TCP listeners.
//!
//! Main entrypoint of the crate: [OnionTransport]
//!
//! ## Example
//! ```no_run
//! # use async_std_crate as async_std;
//! # use libp2p_core::Transport;
//! # async fn test_func() -> Result<(), Box<dyn std::error::Error>> {
//! let address = "/dns/www.torproject.org/tcp/1000".parse()?;
//! let mut transport = libp2p_onion::OnionAsyncStdNativeTlsTransport::bootstrapped().await?;
//! // we have achieved tor connection
//! let _conn = transport.dial(address)?.await?;
//! # Ok(())
//! # }
//! # async_std::task::block_on(async { test_func().await.unwrap() });
//! ```

use std::sync::Arc;
use std::{marker::PhantomData, pin::Pin};

use address::{dangerous_extract_tor_address, safe_extract_tor_address};
use arti_client::{DataStream, TorClient, TorClientBuilder};
use futures::{future::BoxFuture, FutureExt};
use libp2p_core::{transport::TransportError, Multiaddr, Transport};
use tor_rtcompat::Runtime;

mod address;
mod provider;

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
#[doc(inline)]
pub use provider::OnionTokioStream;

use provider::OnionStream;

pub type OnionError = arti_client::Error;

#[derive(Clone)]
pub struct OnionTransport<R: Runtime, S> {
    // client is in an Arc, because wihtout it the Transport::Dial method can't be implemented,
    // due to lifetime issues. With the, eventual, stabilization of static async traits this issue
    // will be resolved.
    client: Arc<TorClient<R>>,
    /// The used conversion mode to resolve addresses. One probably shouldn't access this directly.
    /// The usage of [OnionTransport::with_address_conversion] at construction is recommended.
    pub conversion_mode: AddressConversion,
    phantom: PhantomData<S>,
}

/// Configure the onion transport from here.
pub type OnionBuilder<R> = TorClientBuilder<R>;

/// Mode of address conversion. Refer tor [arti_client::TorAddr](https://docs.rs/arti-client/latest/arti_client/struct.TorAddr.html) for details.
#[derive(Debug, Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressConversion {
    /// uses only dns for address resolution (default)
    #[default]
    DnsOnly,
    /// uses ip and dns for addresses
    IpAndDns,
}

impl<R: Runtime, S> OnionTransport<R, S> {
    pub fn from_builder(
        builder: OnionBuilder<R>,
        conversion_mode: AddressConversion,
    ) -> Result<Self, OnionError> {
        let client = Arc::new(builder.create_unbootstrapped()?);
        Ok(Self {
            client,
            conversion_mode,
            phantom: PhantomData::default(),
        })
    }

    pub async fn bootstrap(&self) -> Result<(), OnionError> {
        self.client.bootstrap().await
    }

    pub fn with_address_conversion(&mut self, conversion_mode: AddressConversion) -> &mut Self {
        self.conversion_mode = conversion_mode;
        self
    }
}

macro_rules! default_constructor {
    () => {
        pub async fn bootstrapped() -> Result<Self, OnionError> {
            let builder = Self::builder();
            let ret = Self::from_builder(builder, AddressConversion::DnsOnly)?;
            ret.bootstrap().await?;
            Ok(ret)
        }
    };
}

#[cfg(all(feature = "native-tls", feature = "async-std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "native-tls", feature = "async-std"))))]
impl<S> OnionTransport<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime, S> {
    pub fn builder() -> OnionBuilder<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime> {
        let runtime = tor_rtcompat::async_std::AsyncStdNativeTlsRuntime::current()
            .expect("Couldn't get the current async_std native-tls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "rustls", feature = "async-std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rustls", feature = "async-std"))))]
impl<S> OnionTransport<tor_rtcompat::async_std::AsyncStdRustlsRuntime, S> {
    pub fn builder() -> OnionBuilder<tor_rtcompat::async_std::AsyncStdRustlsRuntime> {
        let runtime = tor_rtcompat::async_std::AsyncStdRustlsRuntime::current()
            .expect("Couldn't get the current async_std rustls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "native-tls", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "native-tls", feature = "tokio"))))]
impl<S> OnionTransport<tor_rtcompat::tokio::TokioNativeTlsRuntime, S> {
    pub fn builder() -> OnionBuilder<tor_rtcompat::tokio::TokioNativeTlsRuntime> {
        let runtime = tor_rtcompat::tokio::TokioNativeTlsRuntime::current()
            .expect("Couldn't get the current tokio native-tls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "rustls", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rustls", feature = "tokio"))))]
impl<S> OnionTransport<tor_rtcompat::tokio::TokioRustlsRuntime, S> {
    pub fn builder() -> OnionBuilder<tor_rtcompat::tokio::TokioRustlsRuntime> {
        let runtime = tor_rtcompat::tokio::TokioRustlsRuntime::current()
            .expect("Couldn't get the current tokio rustls runtime");
        TorClient::with_runtime(runtime)
    }
    default_constructor!();
}

#[cfg(all(feature = "native-tls", feature = "async-std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "native-tls", feature = "async-std"))))]
pub type AsyncStdNativeTlsOnionTransport =
    OnionTransport<tor_rtcompat::async_std::AsyncStdNativeTlsRuntime, DataStream>;
#[cfg(all(feature = "rustls", feature = "async-std"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rustls", feature = "async-std"))))]
pub type OnionAsyncStdRustlsTransport =
    OnionTransport<tor_rtcompat::async_std::AsyncStdRustlsRuntime, DataStream>;
#[cfg(all(feature = "native-tls", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "native-tls", feature = "tokio"))))]
pub type OnionTokioNativeTlsTransport =
    OnionTransport<tor_rtcompat::tokio::TokioNativeTlsRuntime, OnionTokioStream>;
#[cfg(all(feature = "rustls", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "rustls", feature = "tokio"))))]
pub type OnionTokioRustlsTransport =
    OnionTransport<tor_rtcompat::tokio::TokioRustlsRuntime, OnionTokioStream>;

#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysErrorListenerUpgrade<S>(PhantomData<S>);

impl<S> core::future::Future for AlwaysErrorListenerUpgrade<S> {
    type Output = Result<S, OnionError>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        panic!("onion services are not implented yet, since arti doesn't support it. (awaiting Arti 1.2.0)")
    }
}

impl<R: Runtime, S> Transport for OnionTransport<R, S>
where
    S: OnionStream,
{
    type Output = S;
    type Error = OnionError;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;
    type ListenerUpgrade = AlwaysErrorListenerUpgrade<Self::Output>;

    /// Always returns `TransportError::MultiaddrNotSupported`
    fn listen_on(
        &mut self,
        addr: libp2p_core::Multiaddr,
    ) -> Result<
        libp2p_core::transport::ListenerId,
        libp2p_core::transport::TransportError<Self::Error>,
    > {
        // although this address might be supported, this is returned in order to not provoke an
        // error when trying to listen on this transport.
        Err(TransportError::MultiaddrNotSupported(addr))
    }

    fn remove_listener(&mut self, _id: libp2p_core::transport::ListenerId) -> bool {
        false
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        let maybe_tor_addr = match self.conversion_mode {
            AddressConversion::DnsOnly => safe_extract_tor_address(&addr),
            AddressConversion::IpAndDns => dangerous_extract_tor_address(&addr),
        };

        let tor_address = maybe_tor_addr.ok_or(TransportError::MultiaddrNotSupported(addr))?;
        let onion_client = self.client.clone();

        Ok(async move { onion_client.connect(tor_address).await.map(S::from) }.boxed())
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.dial(addr)
    }

    fn address_translation(&self, _listen: &Multiaddr, _observed: &Multiaddr) -> Option<Multiaddr> {
        None
    }

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p_core::transport::TransportEvent<Self::ListenerUpgrade, Self::Error>>
    {
        // pending is returned here because this transport doesn't support listening
        std::task::Poll::Pending
    }
}

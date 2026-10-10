/// All the possible error in this crate
#[derive(Debug)]
pub enum Error {
    /// Wrapper of io Error
    Io(std::io::Error),

    /// Wrapper of bitcoind Error
    Bitcoind(bitcoind::Error),

    /// Wrapper of electrum_client Error
    ElectrumClient(electrum_client::Error),

    /// Wrapper of bitcoincore_rpc Error
    BitcoinCoreRpc(bitcoind::bitcoincore_rpc::Error),

    /// Wrapper of nix Error
    #[cfg(not(target_os = "windows"))]
    Nix(nix::Error),

    /// Wrapper of early exit status
    EarlyExit(std::process::ExitStatus),

    /// Returned when both tmpdir and staticdir is specified in `Conf` options
    BothDirsSpecified,

    /// Returned when calling methods requiring the bitcoind executable but none is found
    /// (no feature, no `ELECTRS_EXEC`, no `electrs` in `PATH` )
    NoElectrsExecutableFound,

    /// Returned if both env vars `ELECTRS_EXEC` and `ELECTRS_EXE` are found
    BothEnvVars,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Bitcoind(e) => Some(e),
            Error::ElectrumClient(e) => Some(e),
            Error::BitcoinCoreRpc(e) => Some(e),

            #[cfg(not(target_os = "windows"))]
            Error::Nix(e) => Some(e),

            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<bitcoind::Error> for Error {
    fn from(e: bitcoind::Error) -> Self {
        Error::Bitcoind(e)
    }
}

impl From<electrum_client::Error> for Error {
    fn from(e: electrum_client::Error) -> Self {
        Error::ElectrumClient(e)
    }
}

impl From<bitcoind::bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoind::bitcoincore_rpc::Error) -> Self {
        Error::BitcoinCoreRpc(e)
    }
}

#[cfg(not(target_os = "windows"))]
impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        Error::Nix(e)
    }
}

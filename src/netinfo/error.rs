use std::{num, io};

error_chain! {
    foreign_links {
        num::ParseIntError, ParseIntError,
        /// Parser error
        ;

        io::Error, Io,
        /// IO-Error from std::io
        ;
    }

    errors {
        /// Receiving a packet on ethernet channel failed.
        EthernetReceiveError {
            description("failed to read packet from ethernet channel")
        }

        /// Getting a handle to packet-capture-channel failed.
        ChannelCreationError {
            description("error during creation of receiving network packet channel")
        }

        /// Reinterpreting a low level byte-stream as network packet failed.
        PacketConversionError {
            description("reinterpreting a low level byte-stream as network packet failed")
        }

        /// The packet capture code might be missing a packet/network type. Unhandled code paths throw this error.
        UnknownNetworkObject {
            description("unknown/unimplemented network object")
        }

        /// This crate works with non-loopback devices -> packets that are incoming and outgoing are unexpected.
        /// This case should never happen and it stops the program, but in reality, it can be ignored. Please
        /// raise an issue, so the case can be discussed and this error removed.
        LocalToLocalConnectionError {
            description("packet on loopback device has local-to-local connection")
        }

        /// Reading a /proc/net/tcp{6} or /proc/net/udp{6} file failed
        ProcNetFileError(path: String, error: io::Error) {
            description("error when attempting to read /proc/net file")
            display("error when attempting to read /proc/net file: '{}' ({})", path, error)
        }

        /// An /proc/net/tcp{6} or /proc/net/udp{6} exists but does not have correct formatting.
        ProcNetFileHasWrongFormat {
            description("an /proc/net/tcp{6} or /proc/net/udp{6} exists but does not have correct formatting")
        }
    }
}

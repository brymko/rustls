use crate::conn::Connection;
use std::io::{IoSlice, Read, Result, Write};
use std::sync::{Arc, Mutex};

/// This type implements `io::Read` and `io::Write`, encapsulating
/// a Connection `C` and an underlying transport `T`, such as a socket.
///
/// This allows you to use a rustls Connection like a normal stream.
#[derive(Debug)]
pub struct Stream<'a, C: 'a + Connection + ?Sized, T: 'a + Read + Write + ?Sized> {
    /// Our TLS connection
    pub conn: &'a mut C,

    /// The underlying transport, like a socket
    pub sock: &'a mut T,
}

impl<'a, C, T> Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    /// Make a new Stream using the Connection `conn` and socket-like object
    /// `sock`.  This does not fail and does no IO.
    pub fn new(conn: &'a mut C, sock: &'a mut T) -> Stream<'a, C, T> {
        Stream { conn, sock }
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> Result<()> {
        if self.conn.is_handshaking() {
            self.conn.complete_io(self.sock)?;
        }

        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }

        Ok(())
    }
}

impl<'a, C, T> Read for Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. Otherwise, we will prematurely signal EOF by returning 0. We
        // determine if EOF has actually been hit by checking if 0 bytes were
        // read from the underlying transport.
        while self.conn.wants_read() {
            let at_eof = self.conn.complete_io(self.sock)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.conn.process_new_packets() {
                    if at_eof && io_state.plaintext_bytes_to_read() == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        self.conn.reader().read(buf)
    }
}

impl<'a, C, T> Write for Stream<'a, C, T>
where
    C: 'a + Connection,
    T: 'a + Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self.conn.writer().write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self.conn.complete_io(self.sock);

        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self
            .conn
            .writer()
            .write_vectored(bufs)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self.conn.complete_io(self.sock);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.conn.writer().flush()?;
        if self.conn.wants_write() {
            self.conn.complete_io(self.sock)?;
        }
        Ok(())
    }
}

/// This type implements `io::Read` and `io::Write`, encapsulating
/// and owning a Connection `C` and an underlying blocking transport
/// `T`, such as a socket.
///
/// This allows you to use a rustls Connection like a normal stream.
#[derive(Debug)]
pub struct StreamOwned<C: Connection + Sized, T: Read + Write + Sized> {
    /// Our conneciton
    pub conn: C,

    /// The underlying transport, like a socket
    pub sock: T,
}

impl<C, T> StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    /// Make a new StreamOwned taking the Connection `conn` and socket-like
    /// object `sock`.  This does not fail and does no IO.
    ///
    /// This is the same as `Stream::new` except `conn` and `sock` are
    /// moved into the StreamOwned.
    pub fn new(conn: C, sock: T) -> StreamOwned<C, T> {
        StreamOwned { conn, sock }
    }

    /// Get a reference to the underlying socket
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }
}

impl<'a, C, T> StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn as_stream(&'a mut self) -> Stream<'a, C, T> {
        Stream {
            conn: &mut self.conn,
            sock: &mut self.sock,
        }
    }
}

impl<C, T> Read for StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.as_stream().read(buf)
    }
}

impl<C, T> Write for StreamOwned<C, T>
where
    C: Connection,
    T: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.as_stream().write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.as_stream().flush()
    }
}

/// This type implements `io::Read` and `io::Write`, encapsulating
/// and owning a Connection `C` and an underlying blocking transport
/// `T`, such as a socket.
///
/// This allows you to use a rustls Connection like a normal stream.
/// This type is also clonable and uses the Arc<Mutex> combo for the `Connection`.
#[derive(Debug)]
pub struct StreamClonabel<C: Connection + Sized, T: Read + Write + Sized + Clone> {
    /// Connection.
    pub conn: Arc<Mutex<C>>,
    /// Stream.
    pub sock: T,
}

impl<C, T> Clone for StreamClonabel<C, T>
where
    C: Connection,
    T: Read + Write + Clone,
{
    fn clone(&self) -> Self {
        Self {
            conn: Arc::clone(&self.conn),
            sock: self.sock.clone(),
        }
    }
}

impl<C, T> StreamClonabel<C, T>
where
    C: Connection,
    T: Read + Write + Clone,
{
    /// Make a new StreamOwned taking the Connection `conn` and socket-like
    /// object `sock`.  This does not fail and does no IO.
    ///
    /// This is the same as `Stream::new` except `conn` and `sock` are
    /// moved into the StreamClonabel.
    pub fn new(conn: C, sock: T) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            sock,
        }
    }

    /// Get a reference to the underlying socket
    pub fn get_ref(&self) -> &T {
        &self.sock
    }

    /// Get a mutable reference to the underlying socket
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.sock
    }

    /// If we're handshaking, complete all the IO for that.
    /// If we have data to write, write it all.
    fn complete_prior_io(&mut self) -> Result<()> {
        if self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .is_handshaking()
        {
            self.conn
                .lock()
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?
                .complete_io(&mut self.sock)?;
        }

        if self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .wants_write()
        {
            self.conn
                .lock()
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?
                .complete_io(&mut self.sock)?;
        }

        Ok(())
    }
}

impl<C, T> Read for StreamClonabel<C, T>
where
    C: Connection,
    T: Read + Write + Clone,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // code copy from Stream::read
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. Otherwise, we will prematurely signal EOF by returning 0. We
        // determine if EOF has actually been hit by checking if 0 bytes were
        // read from the underlying transport.
        while self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .wants_read()
        {
            let at_eof = self
                .conn
                .lock()
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?
                .complete_io(&mut self.sock)?
                .0
                == 0;
            if at_eof {
                if let Ok(io_state) = self
                    .conn
                    .lock()
                    .map_err(|_| std::io::ErrorKind::BrokenPipe)?
                    .process_new_packets()
                {
                    if at_eof && io_state.plaintext_bytes_to_read() == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        self.conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .reader()
            .read(buf)
    }
}

impl<C, T> Write for StreamClonabel<C, T>
where
    C: Connection,
    T: Read + Write + Clone,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .writer()
            .write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        // ????????????????? dafuq
        let _ = self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .complete_io(&mut self.sock);

        Ok(len)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
        self.complete_prior_io()?;

        let len = self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .writer()
            .write_vectored(bufs)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .complete_io(&mut self.sock);

        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.complete_prior_io()?;

        self.conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .writer()
            .flush()?;
        if self
            .conn
            .lock()
            .map_err(|_| std::io::ErrorKind::BrokenPipe)?
            .wants_write()
        {
            self.conn
                .lock()
                .map_err(|_| std::io::ErrorKind::BrokenPipe)?
                .complete_io(&mut self.sock)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, StreamClonabel, StreamOwned};
    use crate::client::ClientConnection;
    use crate::conn::Connection;
    use crate::server::ServerConnection;
    use std::net::TcpStream;

    #[test]
    fn stream_can_be_created_for_connection_and_tcpstream() {
        type _Test<'a> = Stream<'a, dyn Connection, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_client_and_tcpstream() {
        type _Test = StreamOwned<ClientConnection, TcpStream>;
    }

    #[test]
    fn streamowned_can_be_created_for_server_and_tcpstream() {
        type _Test = StreamOwned<ServerConnection, TcpStream>;
    }

    #[test]
    fn streamcloned_can_be_created_for_client_and_tcpstream() {
        struct CloneDummy {
            stream: TcpStream,
        }

        impl Clone for CloneDummy {
            fn clone(&self) -> Self {
                Self {
                    stream: self.stream.try_clone().unwrap(),
                }
            }
        }

        type _Test = StreamClonabel<ClientConnection, TcpStream>;
    }
}

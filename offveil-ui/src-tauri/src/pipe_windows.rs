//! Named-pipe I/O with one absolute RPC deadline, including partial reads.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Instant;
use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, FILE_FLAG_OVERLAPPED};
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};

pub struct DeadlinePipe {
    file: File,
    deadline: Instant,
}

impl DeadlinePipe {
    pub fn open(path: &str, deadline: Instant) -> io::Result<Self> {
        remaining_ms(deadline)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(path)?;
        Ok(Self { file, deadline })
    }

    fn transfer(&self, buffer: *mut u8, len: usize, write: bool) -> io::Result<usize> {
        if len == 0 {
            return Ok(0);
        }
        remaining_ms(self.deadline)?;
        // Each operation has its own manual-reset event and OVERLAPPED. The
        // buffer and both objects remain alive until completion or cancellation.
        unsafe {
            let event = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
            if event.is_null() {
                return Err(io::Error::last_os_error());
            }
            let event = OwnedHandle::from_raw_handle(event);
            let handle = self.file.as_raw_handle();
            let mut operation: OVERLAPPED = std::mem::zeroed();
            operation.hEvent = event.as_raw_handle();
            let mut transferred = 0;
            let len = len.min(u32::MAX as usize) as u32;
            let completed = if write {
                WriteFile(handle, buffer, len, &mut transferred, &mut operation)
            } else {
                ReadFile(handle, buffer, len, &mut transferred, &mut operation)
            };
            if completed != 0 {
                return Ok(transferred as usize);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
            let result = remaining_ms(self.deadline).and_then(|wait| {
                if GetOverlappedResultEx(handle, &operation, &mut transferred, wait, 0) != 0 {
                    Ok(transferred as usize)
                } else {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                        Err(deadline_error())
                    } else {
                        Err(error)
                    }
                }
            });
            if result.is_err() {
                // CancelIoEx does not wait. Drain the cancellation before the
                // stack OVERLAPPED or caller's buffer can be dropped/reused.
                let _ = CancelIoEx(handle, &operation);
                let _ = GetOverlappedResult(handle, &operation, &mut transferred, 1);
            }
            result
        }
    }
}

fn deadline_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "RPC deadline elapsed")
}

fn remaining_ms(deadline: Instant) -> io::Result<u32> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .map(|remaining| remaining.as_millis().clamp(1, (u32::MAX - 1) as u128) as u32)
        .ok_or_else(deadline_error)
}

impl Read for DeadlinePipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.transfer(buffer.as_mut_ptr(), buffer.len(), false)
    }
}

impl Write for DeadlinePipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.transfer(buffer.as_ptr() as *mut u8, buffer.len(), true)
    }

    fn flush(&mut self) -> io::Result<()> {
        // Writes complete before returning. FlushFileBuffers would additionally
        // wait for the peer to consume data, outside the RPC deadline.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    fn server(work: impl FnOnce(File) + Send + 'static) -> (String, thread::JoinHandle<()>) {
        let path = format!(r"\\.\pipe\offveil-test-{}", uuid::Uuid::new_v4());
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                256,
                256,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let file = unsafe { File::from_raw_handle(handle) };
        let worker = thread::spawn(move || {
            let connected = unsafe { ConnectNamedPipe(file.as_raw_handle(), std::ptr::null_mut()) };
            if connected == 0 {
                assert_eq!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(ERROR_PIPE_CONNECTED as i32)
                );
            }
            work(file);
        });
        (path, worker)
    }

    #[test]
    fn stalled_read_is_cancelled_at_deadline() {
        let (path, worker) = server(|_peer| thread::sleep(Duration::from_millis(300)));
        let began = Instant::now();
        let mut pipe = DeadlinePipe::open(&path, began + Duration::from_millis(70)).unwrap();
        assert_eq!(
            pipe.read(&mut [0; 8]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() < Duration::from_millis(250));
        drop(pipe);
        worker.join().unwrap();
    }

    #[test]
    fn stalled_write_is_cancelled_at_deadline() {
        let (path, worker) = server(|_peer| thread::sleep(Duration::from_millis(300)));
        let began = Instant::now();
        let mut pipe = DeadlinePipe::open(&path, began + Duration::from_millis(70)).unwrap();
        assert_eq!(
            pipe.write_all(&vec![0; 1024 * 1024]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() < Duration::from_millis(250));
        drop(pipe);
        worker.join().unwrap();
    }

    #[test]
    fn partial_reads_share_one_deadline() {
        let (path, worker) = server(|mut peer| {
            for _ in 0..30 {
                thread::sleep(Duration::from_millis(20));
                if peer.write_all(b" ").is_err() {
                    break;
                }
            }
        });
        let began = Instant::now();
        let pipe = DeadlinePipe::open(&path, began + Duration::from_millis(100)).unwrap();
        let mut reader = BufReader::new(pipe);
        assert_eq!(
            reader.read_line(&mut String::new()).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() < Duration::from_millis(350));
        drop(reader);
        worker.join().unwrap();
    }

    #[test]
    fn request_and_response_still_work() {
        let (path, worker) = server(|peer| {
            let mut reader = BufReader::new(peer);
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            assert_eq!(request, "ping\n");
            reader.get_mut().write_all(b"pong\n").unwrap();
            // Keep the server handle alive until the client consumes the reply.
            let _ = reader.read_line(&mut String::new());
        });
        let mut pipe = DeadlinePipe::open(&path, Instant::now() + Duration::from_secs(2)).unwrap();
        pipe.write_all(b"ping\n").unwrap();
        let mut reader = BufReader::new(pipe);
        let mut reply = String::new();
        reader.read_line(&mut reply).unwrap();
        assert_eq!(reply, "pong\n");
        drop(reader);
        worker.join().unwrap();
    }
}

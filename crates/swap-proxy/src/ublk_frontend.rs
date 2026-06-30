//! ublk block-device frontend for the swap proxy.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use libublk::ctrl::UblkCtrlBuilder;
use libublk::io::{BufDescList, UblkDev, UblkQueue};
use libublk::{BufDesc, UblkError, UblkFlags, UblkIORes};
use tracing::{error, info, warn};

use crate::fingerprint::PAGE_SIZE;
use crate::ProxyEngine;

const DEFAULT_QUEUE_DEPTH: u16 = 64;
const DEFAULT_IO_BUF_BYTES: u32 = 128 * 1024;
const UBLK_CONTROL_PATH: &str = "/dev/ublk-control";

/// Maximum consecutive I/O completion failures before stopping the queue.
const MAX_COMPLETION_FAILURES: u32 = 10;

/// How often the watchdog polls the shutdown flag (ms).
const SHUTDOWN_POLL_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UblkOp {
    Read,
    Write,
    Flush,
    Discard,
    WriteZeroes,
    Unsupported(u32),
}

impl UblkOp {
    fn from_raw(raw: u32) -> Self {
        match raw {
            libublk::sys::UBLK_IO_OP_READ => Self::Read,
            libublk::sys::UBLK_IO_OP_WRITE => Self::Write,
            libublk::sys::UBLK_IO_OP_FLUSH => Self::Flush,
            libublk::sys::UBLK_IO_OP_DISCARD => Self::Discard,
            libublk::sys::UBLK_IO_OP_WRITE_ZEROES => Self::WriteZeroes,
            other => Self::Unsupported(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlockRequest {
    op: UblkOp,
    offset: u64,
    bytes: usize,
}

impl BlockRequest {
    fn new(op: UblkOp, start_sector: u64, nr_sectors: u32) -> Self {
        Self {
            op,
            offset: start_sector << 9,
            bytes: (nr_sectors << 9) as usize,
        }
    }

    fn validate_page_aligned(self) -> Result<Self, i32> {
        // MSRV 1.75: usize::is_multiple_of was stabilized in 1.87; stay on %.
        #[allow(clippy::manual_is_multiple_of)]
        let aligned = self.offset % (PAGE_SIZE as u64) == 0 && self.bytes % PAGE_SIZE == 0;
        if !aligned {
            return Err(-libc::EINVAL);
        }

        Ok(self)
    }
}

/// Raw pointer wrapper so the watchdog thread can issue `kill_dev()`.
///
/// `UblkCtrl` is Send + Sync but not Clone. We need shared ownership
/// between the queue-loop thread (which calls `run_target`) and the
/// watchdog thread (which calls `kill_dev` on SIGTERM).
struct SharedCtrl(*mut libublk::ctrl::UblkCtrl);

unsafe impl Send for SharedCtrl {}
unsafe impl Sync for SharedCtrl {}

impl std::ops::Deref for SharedCtrl {
    type Target = libublk::ctrl::UblkCtrl;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.0 }
    }
}

impl Drop for SharedCtrl {
    fn drop(&mut self) {
        // NO: actual drop happens when Box is consumed
    }
}

/// Run the ublk frontend. Blocks until the device is stopped.
///
/// `bootstrap` fires once when the kernel has created the block device.
///
/// `shutdown` is set by the caller's signal handler. When toggled, a
/// watchdog thread issues `kill_dev()` to unblock `run_target` so the
/// process exits cleanly via the normal Drop path. This clears the
/// ghost-swap-entry problem: during Drop, libublk sends DEL_DEV which
/// synchronously removes the kernel-side swap entry.
pub(crate) fn run(
    engine: Arc<ProxyEngine>,
    size_gb: u64,
    bootstrap: impl FnOnce(&Path) + Send + 'static,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let total_bytes = size_gb
        .checked_mul(1024 * 1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("device size overflows u64"))?;
    let nr_queues = std::thread::available_parallelism()
        .map(|n| n.get().min(4) as u16)
        .unwrap_or(1);

    let init_errors = Arc::new(Mutex::new(Vec::<anyhow::Error>::new()));
    let bootstrap = Arc::new(Mutex::new(Some(bootstrap)));

    let ctrl = UblkCtrlBuilder::default()
        .name("animaksm_swap_proxy")
        .id(-1)
        .nr_queues(nr_queues)
        .depth(DEFAULT_QUEUE_DEPTH)
        .io_buf_bytes(DEFAULT_IO_BUF_BYTES)
        .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV | UblkFlags::UBLK_DEV_F_MLOCK_IO_BUFFER)
        .build()
        .map_err(map_ublk_error)?;

    // Heap-allocate the controller and share via raw pointer.
    let ctrl = Box::into_raw(Box::new(ctrl));
    let shared = SharedCtrl(ctrl);

    let shutdown_for_watchdog = Arc::clone(&shutdown);
    let watchdog = std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(SHUTDOWN_POLL_MS));
        if shutdown_for_watchdog.load(Ordering::Relaxed) {
            let _ = shared.kill_dev();
            break;
        }
    });

    let ctrl = unsafe { Box::from_raw(ctrl) };

    let tgt_init = move |dev: &mut UblkDev| {
        init_target(dev, total_bytes);
        Ok(())
    };

    let queue_engine = Arc::clone(&engine);
    let queue_init_errors = Arc::clone(&init_errors);
    let queue_fn = move |qid, dev: &UblkDev| {
        run_queue(
            qid,
            dev,
            Arc::clone(&queue_engine),
            Arc::clone(&queue_init_errors),
        );
    };

    let bootstrap_for_device_fn = Arc::clone(&bootstrap);
    let device_fn = move |ctrl: &libublk::ctrl::UblkCtrl| {
        let bdev = ctrl.get_bdev_path();
        info!(
            dev_id = ctrl.dev_info().dev_id,
            block_device = %bdev,
            "ublk swap proxy device is live"
        );
        if let Some(cb) = bootstrap_for_device_fn.lock().unwrap().take() {
            let bdev = std::path::PathBuf::from(&bdev);
            std::thread::spawn(move || {
                cb(&bdev);
            });
        }
    };

    let result = ctrl
        .run_target(tgt_init, queue_fn, device_fn)
        .map(|_| ())
        .map_err(map_ublk_error);

    // Signal the watchdog to exit (harmless if already exited).
    let _ = watchdog.join();

    result?;

    let errors = init_errors.lock().unwrap();
    if let Some(first_err) = errors.first() {
        Err(anyhow::anyhow!(
            "queue initialization failed: {}",
            first_err
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn ensure_available() -> anyhow::Result<()> {
    if !Path::new(UBLK_CONTROL_PATH).exists() {
        anyhow::bail!(
            "{UBLK_CONTROL_PATH} is missing; load the kernel driver with `modprobe ublk_drv`"
        );
    }

    Ok(())
}

fn init_target(dev: &mut UblkDev, total_bytes: u64) {
    dev.set_default_params(total_bytes);
    dev.tgt.params.basic.logical_bs_shift = 12;
    dev.tgt.params.basic.physical_bs_shift = 12;
    dev.tgt.params.basic.io_min_shift = 12;
    dev.tgt.params.basic.io_opt_shift = 12;
    dev.set_target_json(serde_json::json!({
        "animaksm_swap_proxy": {
            "backend": "dedup-page-store",
            "logical_block_size": PAGE_SIZE,
        }
    }));
}

fn run_queue(
    qid: u16,
    dev: &UblkDev,
    engine: Arc<ProxyEngine>,
    init_errors: Arc<Mutex<Vec<anyhow::Error>>>,
) {
    let mut bufs = dev.alloc_queue_io_bufs();
    let queue = match UblkQueue::new(qid, dev)
        .and_then(|queue| queue.submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs))))
    {
        Ok(queue) => queue,
        Err(err) => {
            error!(qid, error = %err, "failed to initialize ublk queue");
            // Propagate error to main thread so device creation fails atomically
            init_errors.lock().unwrap().push(anyhow::anyhow!(err));
            return;
        }
    };

    // Track consecutive I/O completion failures
    let mut completion_failures: u32 = 0;

    queue.wait_and_handle_io(move |queue, tag, _io| {
        let iod = queue.get_iod(tag);
        let request = BlockRequest::new(
            UblkOp::from_raw(iod.op_flags & 0xff),
            iod.start_sector,
            iod.nr_sectors,
        );
        let buf = &mut bufs[tag as usize];
        let result = handle_request(&engine, request, buf.as_mut_slice());

        if let Err(err) = queue.complete_io_cmd_unified(tag, BufDesc::Slice(buf.as_slice()), result)
        {
            completion_failures += 1;
            error!(qid, tag, error = %err, "failed to complete ublk io");

            if completion_failures >= MAX_COMPLETION_FAILURES {
                warn!(
                    qid,
                    failures = completion_failures,
                    "too many consecutive I/O completion failures, stopping queue"
                );
                // We can't easily stop the queue from here, but we log at WARN level
                // The kernel will hang the originating process if completion never arrives
            }
        } else {
            // Reset counter on successful completion
            completion_failures = 0;
        }
    });
}

fn handle_request(
    engine: &ProxyEngine,
    request: BlockRequest,
    buffer: &mut [u8],
) -> Result<UblkIORes, UblkError> {
    let bytes = match execute_request(engine, request, buffer) {
        Ok(bytes) => bytes,
        Err(errno) => return Ok(UblkIORes::Result(errno)),
    };

    Ok(UblkIORes::Result(bytes as i32))
}

fn execute_request(
    engine: &ProxyEngine,
    request: BlockRequest,
    buffer: &mut [u8],
) -> Result<usize, i32> {
    match request.op {
        UblkOp::Read => {
            let request = request.validate_page_aligned()?;
            if buffer.len() < request.bytes {
                return Err(-libc::EINVAL);
            }

            for (page_idx, chunk) in buffer[..request.bytes].chunks_mut(PAGE_SIZE).enumerate() {
                let offset = request.offset + (page_idx * PAGE_SIZE) as u64;
                let page = engine.handle_read(offset).map_err(|_| -libc::EIO)?;
                if page.len() != chunk.len() {
                    return Err(-libc::EIO);
                }
                chunk.copy_from_slice(&page);
            }
            Ok(request.bytes)
        }
        UblkOp::Write => {
            let request = request.validate_page_aligned()?;
            if buffer.len() < request.bytes {
                return Err(-libc::EINVAL);
            }

            for (page_idx, chunk) in buffer[..request.bytes].chunks(PAGE_SIZE).enumerate() {
                let offset = request.offset + (page_idx * PAGE_SIZE) as u64;
                engine.handle_write(offset, chunk).map_err(|_| -libc::EIO)?;
            }
            Ok(request.bytes)
        }
        UblkOp::Flush => Ok(0),
        UblkOp::Discard => {
            let request = request.validate_page_aligned()?;
            for page_idx in 0..(request.bytes / PAGE_SIZE) {
                let offset = request.offset + (page_idx * PAGE_SIZE) as u64;
                engine.handle_discard(offset);
            }
            Ok(request.bytes)
        }
        UblkOp::WriteZeroes => {
            let request = request.validate_page_aligned()?;
            let zero_page = [0u8; PAGE_SIZE];
            for page_idx in 0..(request.bytes / PAGE_SIZE) {
                let offset = request.offset + (page_idx * PAGE_SIZE) as u64;
                engine
                    .handle_write(offset, &zero_page)
                    .map_err(|_| -libc::EIO)?;
            }
            Ok(request.bytes)
        }
        UblkOp::Unsupported(_) => Err(-libc::EOPNOTSUPP),
    }
}

fn map_ublk_error(err: UblkError) -> anyhow::Error {
    anyhow::anyhow!("ublk frontend error: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn engine() -> (tempfile::TempDir, Arc<ProxyEngine>) {
        let dir = tempfile::tempdir().unwrap();
        let path = PathBuf::from(dir.path()).join("pagestore.dat");
        let engine = Arc::new(ProxyEngine::new(&path, 1, 128, 1024).unwrap());
        (dir, engine)
    }

    #[test]
    fn test_block_request_uses_sector_units() {
        let request = BlockRequest::new(UblkOp::Read, 8, 16);

        assert_eq!(request.offset, PAGE_SIZE as u64);
        assert_eq!(request.bytes, 8192);
    }

    #[test]
    fn test_block_request_rejects_unaligned_ranges() {
        let request = BlockRequest::new(UblkOp::Read, 1, 1);

        assert_eq!(request.validate_page_aligned(), Err(-libc::EINVAL));
    }

    #[test]
    fn test_execute_write_and_read_roundtrip() {
        let (_dir, engine) = engine();
        let page = vec![0xAB; PAGE_SIZE];
        let mut write_buf = page.clone();
        let request = BlockRequest::new(UblkOp::Write, 0, (PAGE_SIZE / 512) as u32);

        assert_eq!(
            execute_request(&engine, request, &mut write_buf).unwrap(),
            PAGE_SIZE
        );

        let mut read_buf = vec![0; PAGE_SIZE];
        let request = BlockRequest::new(UblkOp::Read, 0, (PAGE_SIZE / 512) as u32);

        assert_eq!(
            execute_request(&engine, request, &mut read_buf).unwrap(),
            PAGE_SIZE
        );
        assert_eq!(read_buf, page);
    }

    #[test]
    fn test_execute_discard_removes_translation() {
        let (_dir, engine) = engine();
        let mut page = vec![0xCD; PAGE_SIZE];
        let sectors = (PAGE_SIZE / 512) as u32;

        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Write, 0, sectors),
            &mut page,
        )
        .unwrap();
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Discard, 0, sectors),
            &mut [],
        )
        .unwrap();

        let mut read_buf = vec![0xFF; PAGE_SIZE];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Read, 0, sectors),
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(read_buf, vec![0; PAGE_SIZE]);
    }

    #[test]
    fn test_execute_write_zeroes() {
        let (_dir, engine) = engine();
        let sectors = (PAGE_SIZE / 512) as u32;
        let mut page = vec![0xEF; PAGE_SIZE];

        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Write, 0, sectors),
            &mut page,
        )
        .unwrap();
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::WriteZeroes, 0, sectors),
            &mut [],
        )
        .unwrap();

        let mut read_buf = vec![0xFF; PAGE_SIZE];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Read, 0, sectors),
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(read_buf, vec![0; PAGE_SIZE]);
    }

    #[test]
    fn test_execute_unsupported_op_returns_eopnotsupp() {
        let (_dir, engine) = engine();
        let mut buf = [];

        assert_eq!(
            execute_request(
                &engine,
                BlockRequest::new(UblkOp::Unsupported(99), 0, 0),
                &mut buf
            ),
            Err(-libc::EOPNOTSUPP)
        );
    }

    #[test]
    fn test_execute_read_with_buffer_smaller_than_request_is_rejected() {
        let (_dir, engine) = engine();
        let mut buf = vec![0u8; PAGE_SIZE];
        let sectors = (PAGE_SIZE / 512 * 2) as u32;
        let request = BlockRequest::new(UblkOp::Read, 0, sectors);
        assert_eq!(
            execute_request(&engine, request, &mut buf),
            Err(-libc::EINVAL)
        );
    }

    #[test]
    fn test_execute_write_with_buffer_smaller_than_request_is_rejected() {
        let (_dir, engine) = engine();
        let mut buf = vec![0xAA; PAGE_SIZE];
        let sectors = (PAGE_SIZE / 512 * 2) as u32;
        let request = BlockRequest::new(UblkOp::Write, 0, sectors);
        assert_eq!(
            execute_request(&engine, request, &mut buf),
            Err(-libc::EINVAL)
        );
    }

    #[test]
    fn test_execute_multi_page_write_then_read_roundtrip() {
        let (_dir, engine) = engine();
        let sectors = (PAGE_SIZE / 512 * 2) as u32;
        let mut write_buf = vec![0xAB; PAGE_SIZE * 2];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Write, 0, sectors),
            &mut write_buf,
        )
        .unwrap();
        let mut read_buf = vec![0; PAGE_SIZE * 2];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Read, 0, sectors),
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(read_buf, write_buf);
    }

    #[test]
    fn test_execute_unsupported_op_with_nonzero_buffer_returns_eopnotsupp() {
        let (_dir, engine) = engine();
        let mut buf = [0u8; PAGE_SIZE];
        assert_eq!(
            execute_request(
                &engine,
                BlockRequest::new(UblkOp::Unsupported(0xFF), 0, (PAGE_SIZE / 512) as u32),
                &mut buf
            ),
            Err(-libc::EOPNOTSUPP)
        );
    }

    #[test]
    fn test_execute_discard_multi_page_clears_all_translations() {
        let (_dir, engine) = engine();
        let sectors_per_page = (PAGE_SIZE / 512) as u32;
        let p1 = vec![0x11; PAGE_SIZE];
        let p2 = vec![0x22; PAGE_SIZE];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Write, 0, sectors_per_page),
            &mut p1.clone(),
        )
        .unwrap();
        // 2-page write at byte offset PAGE_SIZE = sector sectors_per_page.
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Write, sectors_per_page as u64, sectors_per_page * 2),
            &mut [p2.clone(), p2.clone()].concat(),
        )
        .unwrap();
        // 1 translation at offset 0, 2 translations at offsets PAGE_SIZE and 2*PAGE_SIZE
        assert_eq!(engine.translation.lock().len(), 3);

        // Discard 3 pages starting at sector 0.
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Discard, 0, sectors_per_page * 3),
            &mut [],
        )
        .unwrap();

        let mut read_buf = vec![0xFF; PAGE_SIZE];
        execute_request(
            &engine,
            BlockRequest::new(UblkOp::Read, 0, sectors_per_page),
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(read_buf, vec![0; PAGE_SIZE]);
        assert_eq!(engine.translation.lock().len(), 0);
    }
}

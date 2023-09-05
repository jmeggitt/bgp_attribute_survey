//! Upon my first run I found that the parsing was using much less CPU power than I had thought it
//! would. My guess was that this was caused threads sleeping while they waited for more data from
//! the network. To solve this problem, I added a second group of threads separate from rayon's
//! thread pool which handle creating the initial network connection and buffering request data.
//! This solved the issue and improved the parsing speed by about 1.5-2x on my system.
//!
//! Technically, async/await would have been a more appropriate solution, but I don't really like
//! having to work with async/await if I can avoid it. Plus [bgpkit_parser] does not support async
//! and this was quite straightforward to write.
use crate::{MAX_PREFETCH_BUFFER_SIZE, PREFETCH_BUFFER_SPACE};
use bgpkit_broker::BrokerItem;
use crossbeam_channel::{Receiver, Sender};
use std::io;
use std::io::ErrorKind::Other;
use std::io::{BufRead, Read};
use std::sync::atomic::AtomicIsize;
use std::sync::atomic::Ordering::SeqCst;

pub struct PrefetchResult {
    pub url: String,
    pub reader: Box<dyn Read + Send>,
}

pub fn prefetch_iter(
    sources: Vec<BrokerItem>,
    threads: usize,
    mut buffer_limit: usize,
) -> impl Iterator<Item = PrefetchResult> {
    let (send_items, recv_items) = crossbeam_channel::unbounded();
    sources
        .into_iter()
        .try_for_each(|x| send_items.send(x))
        .unwrap();

    buffer_limit = buffer_limit.saturating_sub(threads);
    let (send_result, recv_result) = crossbeam_channel::bounded(buffer_limit);

    for _ in 0..threads {
        let recv = recv_items.clone();
        let send = send_result.clone();
        std::thread::spawn(move || worker_thread(recv, send));
    }

    recv_result.into_iter()
}

static ESTIMATED_SPACE: AtomicIsize = AtomicIsize::new(PREFETCH_BUFFER_SPACE as isize);

fn attempt_to_claim_space(estimated_size: i64) -> Option<isize> {
    if estimated_size <= 0 || estimated_size as usize > MAX_PREFETCH_BUFFER_SIZE {
        return None;
    }

    let estimated_buffer_capacity = 2 * estimated_size as isize;
    ESTIMATED_SPACE
        .fetch_update(SeqCst, SeqCst, |x| {
            (x >= estimated_buffer_capacity).then(|| x - estimated_buffer_capacity)
        })
        .ok()?;

    Some(estimated_buffer_capacity)
}

/// Wrapper around a readable buffer which updates [ESTIMATED_SPACE] when the buffer is dropped.
struct BufferGuard {
    buffer: Vec<u8>,
    index: usize,
    // Should be the same as the buffer's capacity, but store just to be safe
    claimed_space: usize,
}

impl Read for BufferGuard {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read_len = buf.len().min(self.buffer.len() - self.index);
        buf[..read_len].copy_from_slice(&self.buffer[self.index..self.index + read_len]);
        self.index += read_len;
        Ok(read_len)
    }
}

impl BufRead for BufferGuard {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(&self.buffer[self.index..])
    }

    fn consume(&mut self, amt: usize) {
        self.index += amt;
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        let buffer = std::mem::take(&mut self.buffer);
        drop(buffer);
        ESTIMATED_SPACE.fetch_add(self.claimed_space as isize, SeqCst);
    }
}

fn worker_thread(recv: Receiver<BrokerItem>, send: Sender<PrefetchResult>) {
    while let Ok(item) = recv.recv() {
        let reader = match attempt_to_claim_space(item.rough_size) {
            Some(requested_size) => {
                // Pessimistically underside the buffer initially in the hopes of not reaching the
                // approved size limit.
                let mut buffer = Vec::with_capacity(item.rough_size.min(128 << 20) as usize);

                // Read the full message into a buffer
                let response = ureq::get(&item.url)
                    .call()
                    .map_err(|x| io::Error::new(Other, x))
                    .and_then(|x| std::io::copy(&mut x.into_reader(), &mut buffer));

                if let Err(err) = response {
                    println!("Failed to fetch {:?}: {}", item.url, err);
                    continue;
                }

                // Adjust estimated space to account for the differance in size from our estimate
                ESTIMATED_SPACE.fetch_add(requested_size - buffer.capacity() as isize, SeqCst);
                let reader = BufferGuard {
                    claimed_space: buffer.capacity(),
                    buffer,
                    index: 0,
                };

                reader_for_buffer(&item.url, reader)
            }
            None => {
                // Just defer the base case to oneio since it will only process the data as it arrives
                match oneio::get_reader(&item.url) {
                    Ok(v) => v,
                    Err(err) => {
                        println!("Failed to fetch {:?}: {}", item.url, err);
                        continue;
                    }
                }
            }
        };

        send.send(PrefetchResult {
            url: item.url,
            reader,
        })
        .expect("receiver has not been dropped");
    }
}

fn reader_for_buffer(file: &str, buffer: BufferGuard) -> Box<dyn Read + Send> {
    if file.ends_with(".gz") || file.ends_with(".gzip") {
        return Box::new(flate2::bufread::GzDecoder::new(buffer));
    }
    if file.ends_with(".bz2") || file.ends_with(".bz") {
        return Box::new(bzip2::bufread::BzDecoder::new(buffer));
    }
    if file.ends_with(".lz4") || file.ends_with(".lz") {
        return Box::new(lz4::Decoder::new(buffer).unwrap());
    }

    // Unknown, just send it back as-is and hope things go well
    Box::new(buffer)
}

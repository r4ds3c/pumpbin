//! Live capture scaffolding (Npcap/Npcap). Enabled with `--features live-capture`.

use anyhow::Result;

#[cfg(not(feature = "live-capture"))]
use anyhow::bail;

#[derive(Debug, Clone)]
pub struct CaptureDevice {
    pub name: String,
    pub description: String,
}

impl CaptureDevice {
    pub fn label(&self) -> String {
        if self.description.is_empty() {
            self.name.clone()
        } else {
            format!("{} — {}", self.name, self.description)
        }
    }
}

/// List capture interfaces when the `live-capture` feature is enabled.
pub fn list_devices() -> Result<Vec<CaptureDevice>> {
    #[cfg(feature = "live-capture")]
    {
        live_impl::list_devices()
    }
    #[cfg(not(feature = "live-capture"))]
    {
        bail!(
            "Live capture requires building with `--features live-capture` and Npcap/libpcap installed"
        )
    }
}

/// Capture up to `max_packets` from `device`, waiting at most `max_wait_ms`.
pub fn sniff_frames(
    device: &str,
    max_packets: usize,
    timeout_ms: i32,
    max_wait_ms: i32,
) -> Result<Vec<Vec<u8>>> {
    #[cfg(feature = "live-capture")]
    {
        live_impl::sniff_frames(device, max_packets, timeout_ms, max_wait_ms)
    }
    #[cfg(not(feature = "live-capture"))]
    {
        let _ = (device, max_packets, timeout_ms, max_wait_ms);
        bail!(
            "Live capture requires building with `--features live-capture` and Npcap/libpcap installed"
        )
    }
}

#[cfg(feature = "live-capture")]
mod live_impl {
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, Context, Result};
    use pcap::{Capture, Device};

    use super::CaptureDevice;

    pub fn list_devices() -> Result<Vec<CaptureDevice>> {
        let devices = Device::list().context("list capture devices")?;
        Ok(devices
            .into_iter()
            .map(|d| CaptureDevice {
                name: d.name,
                description: d.desc.unwrap_or_default(),
            })
            .collect())
    }

    pub fn sniff_frames(
        device: &str,
        max_packets: usize,
        timeout_ms: i32,
        max_wait_ms: i32,
    ) -> Result<Vec<Vec<u8>>> {
        let dev = Device::list()
            .context("list devices")?
            .into_iter()
            .find(|d| d.name == device)
            .ok_or_else(|| anyhow!("device not found: {device}"))?;
        let mut cap = Capture::from_device(dev)
            .context("open device")?
            .promisc(true)
            .timeout(timeout_ms)
            .open()
            .context("start capture")?;
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(max_wait_ms.max(timeout_ms) as u64);
        while out.len() < max_packets && Instant::now() < deadline {
            match cap.next_packet() {
                Ok(pkt) => out.push(pkt.data.to_vec()),
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }
}

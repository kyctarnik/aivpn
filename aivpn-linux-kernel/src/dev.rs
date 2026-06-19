// SPDX-License-Identifier: GPL-2.0
//! dev.rs — misc device registration and ioctl dispatch for aivpn.ko
//!
//! Updated for the Linux 6.9+/7.x Rust-for-Linux API:
//!   kernel::miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration}
//!   kernel::uaccess::UserSlice
//!   kernel::fs::File

use kernel::prelude::*;
use kernel::miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration};
use kernel::fs::File;
use kernel::uaccess::{UserSlice, UserPtr};

// ── UAPI ioctl numbers (mirrored from include/uapi/aivpn.h) ──────────────────
// _IOW(0xAE, nr, size) = (2<<30)|(magic<<8)|nr|(size<<16)
// _IOR(0xAE, nr, size) = (1<<30)|(magic<<8)|nr|(size<<16)
// _IOWR = (3<<30); _IO = magic<<8|nr

const MAGIC: u32 = 0xAE;
const fn iow(nr: u32, sz: u32) -> u32  { (2 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn ior(nr: u32, sz: u32) -> u32  { (1 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn iowr(nr: u32, sz: u32) -> u32 { (3 << 30) | (MAGIC << 8) | nr | (sz << 16) }
const fn io(nr: u32) -> u32            { (MAGIC << 8) | nr }

// Packed struct sizes matching C definitions (see include/uapi/aivpn.h)
const IOC_SESSION_ADD:         u32 = iow(1,  160);
const IOC_SESSION_DEL:         u32 = iow(2,   16);
const IOC_SESSION_STAT:        u32 = iowr(3,  52);
const IOC_SET_TUN:             u32 = iow(4,    4);
const IOC_SET_UDP_SOCK:        u32 = iow(5,    4);
const IOC_FLUSH:               u32 = io(6);
const IOC_GET_VERSION:         u32 = ior(7,    4);
const IOC_SESSION_UPDATE_TAGS: u32 = iow(8, 4116);
const API_VERSION:             u32 = 2;

// CAP_NET_ADMIN = 12 (linux/capability.h)
const CAP_NET_ADMIN: i32 = 12;

// ── C helper declarations ─────────────────────────────────────────────────────

extern "C" {
    fn aivpn_session_insert(add: *const u8) -> i32;
    fn aivpn_session_remove(session_id: *const u8) -> i32;
    fn aivpn_session_stat(stat: *mut u8) -> i32;
    fn aivpn_session_tags_update(upd: *const u8) -> i32;
    fn aivpn_session_flush();
    fn aivpn_tun_set_device(ifindex: u32) -> i32;
    fn aivpn_udp_hook_install_by_fd(fd: i32) -> i32;
}

// ── Device ────────────────────────────────────────────────────────────────────

#[pin_data]
pub struct AivpnDev {
    #[pin]
    _reg: MiscDeviceRegistration<AivpnDev>,
}

impl AivpnDev {
    pub fn new() -> Result<Pin<KBox<Self>>> {
        let opts = MiscDeviceOptions {
            name: kernel::c_str!("aivpn"),
        };
        KBox::pin_init(
            try_pin_init!(AivpnDev {
                _reg <- MiscDeviceRegistration::<AivpnDev>::register(opts),
            }),
            GFP_KERNEL,
        )
    }
}

/// Convert a raw `usize` ioctl argument to `UserPtr`.
/// SAFETY: the kernel ioctl dispatcher provides this as a user-space address.
#[inline]
fn to_user_ptr(arg: usize) -> UserPtr {
    // SAFETY: UserPtr is a usize newtype; kernel guarantees arg is user-space.
    unsafe { core::mem::transmute(arg) }
}

#[vtable]
impl MiscDevice for AivpnDev {
    type Ptr = ();

    fn open(_file: &File, _reg: &MiscDeviceRegistration<AivpnDev>) -> Result<()> {
        // Restrict /dev/aivpn to CAP_NET_ADMIN processes
        if !unsafe { kernel::bindings::capable(CAP_NET_ADMIN) } {
            return Err(EPERM);
        }
        Ok(())
    }

    fn ioctl((): (), _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            n if n == IOC_SESSION_ADD => {
                let mut buf = [0u8; 160];
                UserSlice::new(to_user_ptr(arg), 160).reader().read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_insert(buf.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_DEL => {
                let mut id = [0u8; 16];
                UserSlice::new(to_user_ptr(arg), 16).reader().read_slice(&mut id)?;
                kernel::error::to_result(unsafe { aivpn_session_remove(id.as_ptr()) })?;
                Ok(0)
            }
            n if n == IOC_SESSION_STAT => {
                let mut buf = [0u8; 52];
                let (mut reader, mut writer) =
                    UserSlice::new(to_user_ptr(arg), 52).reader_writer();
                reader.read_slice(&mut buf[..16])?;
                kernel::error::to_result(unsafe { aivpn_session_stat(buf.as_mut_ptr()) })?;
                writer.write_slice(&buf)?;
                Ok(0)
            }
            n if n == IOC_SET_TUN => {
                let mut b = [0u8; 4];
                UserSlice::new(to_user_ptr(arg), 4).reader().read_slice(&mut b)?;
                kernel::error::to_result(unsafe {
                    aivpn_tun_set_device(u32::from_ne_bytes(b))
                })?;
                Ok(0)
            }
            n if n == IOC_SET_UDP_SOCK => {
                let mut b = [0u8; 4];
                UserSlice::new(to_user_ptr(arg), 4).reader().read_slice(&mut b)?;
                kernel::error::to_result(unsafe {
                    aivpn_udp_hook_install_by_fd(i32::from_ne_bytes(b))
                })?;
                Ok(0)
            }
            n if n == IOC_FLUSH => {
                unsafe { aivpn_session_flush() };
                Ok(0)
            }
            n if n == IOC_GET_VERSION => {
                UserSlice::new(to_user_ptr(arg), 4)
                    .writer()
                    .write_slice(&API_VERSION.to_ne_bytes())?;
                Ok(0)
            }
            n if n == IOC_SESSION_UPDATE_TAGS => {
                let mut buf = [0u8; 4116];
                UserSlice::new(to_user_ptr(arg), 4116)
                    .reader()
                    .read_slice(&mut buf)?;
                kernel::error::to_result(unsafe { aivpn_session_tags_update(buf.as_ptr()) })?;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }
}

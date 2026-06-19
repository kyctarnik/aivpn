// SPDX-License-Identifier: GPL-2.0
//! aivpn kernel module — entry point (Rust control plane)

#![no_std]

use kernel::prelude::*;

mod dev;

extern "C" {
    fn aivpn_session_table_init() -> i32;
    fn aivpn_session_table_fini();
}

module! {
    type: AivpnModule,
    name: "aivpn",
    authors: ["AIVPN contributors"],
    description: "AIVPN kernel data-plane accelerator (optional, auto-detected)",
    license: "GPL",
    params: {},
}

struct AivpnModule {
    _dev: Pin<KBox<dev::AivpnDev>>,
}

impl kernel::Module for AivpnModule {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        // SAFETY: called once at module load before any ioctl can arrive.
        let ret = unsafe { aivpn_session_table_init() };
        if ret != 0 {
            pr_err!("aivpn: session table init failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }
        let dev = dev::AivpnDev::new()?;
        pr_info!("aivpn: module loaded — /dev/aivpn ready\n");
        Ok(Self { _dev: dev })
    }
}

impl Drop for AivpnModule {
    fn drop(&mut self) {
        // SAFETY: misc device deregistered before this runs (via _dev Drop).
        unsafe { aivpn_session_table_fini() };
        pr_info!("aivpn: module unloaded\n");
    }
}

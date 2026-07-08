#ifndef AivpnCoreBridge_h
#define AivpnCoreBridge_h

// Mirrors Tunnel/AivpnCoreBridge.h. The app process links the same
// libaivpn_core.a as the tunnel extension (see project.yml's Aivpn target
// OTHER_LDFLAGS) so BootstrapDiscovery.swift can call
// aivpn_verify_bootstrap_descriptor() without duplicating ed25519 logic in
// Swift. The app never calls aivpn_run_tunnel() or any other tunnel-session
// function declared in this header — those remain exclusive to the
// NEPacketTunnelProvider extension.
#include "aivpn_core.h"

#endif /* AivpnCoreBridge_h */

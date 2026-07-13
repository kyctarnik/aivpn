import SwiftUI

@main
struct AivpnApp: App {
    @StateObject private var vpnManager = VPNManager.shared
    @StateObject private var localization = LocalizationManager.shared
    @Environment(\.scenePhase) private var scenePhase

    private let brandPurple = Color(red: 123 / 255, green: 97 / 255, blue: 255 / 255)

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpnManager)
                .environmentObject(localization)
                .tint(brandPurple)
        }
        .onChange(of: scenePhase) { phase in
            // Skip retry when the user explicitly denied VPN permission — don't
            // re-show the system dialog on every app foreground after a denial.
            if phase == .active, !vpnManager.isManagerLoaded, !vpnManager.permissionDenied {
                vpnManager.retryManagerSetup()
            }
        }
    }
}

import Foundation

/// Manages the ~/Library/LaunchAgents/com.aivpn.client.plist that starts
/// AIVPN automatically when the user logs in.
final class LaunchAgentManager {
    static let shared = LaunchAgentManager()
    private init() {}

    private let label = "com.aivpn.client"

    private var plistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    /// True when the LaunchAgent plist is present on disk.
    var isEnabled: Bool {
        FileManager.default.fileExists(atPath: plistURL.path)
    }

    func setEnabled(_ enabled: Bool) {
        if enabled { install() } else { remove() }
    }

    // MARK: - Private

    private func install() {
        // Resolve the real executable inside the running app bundle.
        let bundlePath = Bundle.main.bundlePath
        let execName = Bundle.main.infoDictionary?["CFBundleExecutable"] as? String ?? "AIVPN"
        let execPath = bundlePath + "/Contents/MacOS/" + execName

        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [execPath],
            "RunAtLoad": true,
            "LimitLoadToSessionType": "Aqua",
        ]

        let dir = plistURL.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: nil)

        guard let data = try? PropertyListSerialization.data(
            fromPropertyList: plist, format: .xml, options: 0
        ) else { return }

        try? data.write(to: plistURL, options: .atomic)
    }

    private func remove() {
        try? FileManager.default.removeItem(at: plistURL)
    }
}

import Combine
import Foundation
import Security
import UIKit

@MainActor
final class LicenseManager: ObservableObject {
    private static let verifyURL = URL(string: "https://shafaykeyauthadmin.lovable.app/api/public/v1/verify-license")!

    @Published private(set) var expirationDate: Date?
    @Published private(set) var isActive = false
    @Published private(set) var isBusy = false
    @Published private(set) var message: String?
    @Published private(set) var contactOwner: String?
    @Published var rememberKey = true

    private let service = "com.SHAFAY.EXTERNAL.external-ios.activation"
    private let keyAccount = "license-key"
    private var lastAttemptAt: Date?

    init() {
        isActive = hasRememberedKey
    }

    var hasRememberedKey: Bool { string(for: keyAccount) != nil }

    func beginLaunchSession() {
        isActive = hasRememberedKey
        message = isActive ? "Ready to use" : "Key required — enter your access key"
    }

    func activate(key: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isBusy else { return }

        if let lastAttemptAt, Date().timeIntervalSince(lastAttemptAt) < 1 {
            message = "Please wait a moment before trying again"
            return
        }

        lastAttemptAt = Date()
        isBusy = true
        message = "Checking access key…"

        Task {
            do {
                let deviceID = UIDevice.current.identifierForVendor?.uuidString ?? "unknown-device"
                var request = URLRequest(url: Self.verifyURL)
                request.httpMethod = "POST"
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                request.setValue("application/json", forHTTPHeaderField: "Accept")
                request.httpBody = try JSONSerialization.data(withJSONObject: [
                    "key": trimmed,
                    "device_id": deviceID
                ])

                let (data, response) = try await URLSession.shared.data(for: request)

                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    throw URLError(.badServerResponse)
                }

                struct VerifyResponse: Decodable {
                    let success: Bool
                    let valid: Bool
                    let expires_at: String?
                }

                let result = try JSONDecoder().decode(VerifyResponse.self, from: data)

                guard result.success, result.valid else {
                    isActive = false
                    message = "Invalid or expired access key"
                    return
                }

                expirationDate = Self.parseExpiration(result.expires_at)

                if rememberKey {
                    save(trimmed, for: keyAccount)
                }

                isActive = true
                message = "Activated successfully"
            } catch {
                isActive = false
                message = "Unable to verify key. Please try again."
            }

            isBusy = false
        }
    }

    func rememberedKey() -> String? { string(for: keyAccount) }

    func refresh() {
        isActive = hasRememberedKey
        message = isActive ? "Ready to use" : "Key required — enter your access key"
    }

    func deactivate() {
        delete(keyAccount)
        isActive = false
        expirationDate = nil
        message = "Activation removed from this device"
    }

    private static func parseExpiration(_ value: String?) -> Date? {
        guard let value else { return nil }
        let formatter = ISO8601DateFormatter()
        return formatter.date(from: value)
    }

    private func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

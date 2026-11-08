import Foundation
import CryptoKit

@main
struct SignRulePackage {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 4 else {
            print("Usage: sign-rule-package <manifest.json> <private-key-path> <signed-output.json>")
            exit(1)
        }
        let keyURL = URL(fileURLWithPath: arguments[2])
        let key: Curve25519.Signing.PrivateKey
        if FileManager.default.fileExists(atPath: keyURL.path) {
            key = try .init(rawRepresentation: Data(contentsOf: keyURL))
        } else {
            key = .init()
            try key.rawRepresentation.write(to: keyURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: arguments[1]))
        let signed = ["payload": data.base64EncodedString(), "signature": try key.signature(for: data).base64EncodedString()]
        try JSONSerialization.data(withJSONObject: signed, options: [.sortedKeys]).write(
            to: URL(fileURLWithPath: arguments[3]), options: .atomic
        )
        print("Public key: " + key.publicKey.rawRepresentation.base64EncodedString())
    }
}

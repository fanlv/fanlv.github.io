import Foundation
import WebKit

@main
struct VerifyRules {
    @MainActor
    static func main() async throws {
        let source = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
        guard let store = WKContentRuleListStore.default() else { fatalError("No WebKit rule store") }
        let id = "veil-publisher-" + UUID().uuidString
        _ = try await store.compileContentRuleList(forIdentifier: id, encodedContentRuleList: source)
        try await store.removeContentRuleList(forIdentifier: id)
        print("PASS Safari compilation")
    }
}

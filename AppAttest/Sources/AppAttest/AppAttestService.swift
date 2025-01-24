import CryptoKit
import DeviceCheck

enum AppAttestServiceError: Error {
    case unsupportedDevice
}

extension Data {
    /// Converts `Data` to a hexadecimal string representation.
    func toHexString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}

public final class AppAttestService: AppAttestProvider {
    let attestationProvider: AttestationProvider
    let challengeProvider: ChallengeProvider

    init(
        attestationProvider: AttestationProvider,
        challengeProvider: ChallengeProvider
    ) {
        self.attestationProvider = attestationProvider
        self.challengeProvider = challengeProvider
    }

    public convenience init(challengeProvider: ChallengeProvider) {
        self.init(
            attestationProvider: DCAppAttestService.shared,
            challengeProvider: challengeProvider
        )
    }

    public func fetchAttestation() async throws -> Data {
        guard attestationProvider.isSupported else {
            throw AppAttestServiceError.unsupportedDevice
        }
        let keyID = try await attestationProvider.generateKey()
        let challenge = """
            {"appInstanceID":"05c666b6-c833-46c2-a4ab-6321fc3cfe8c","timeStamp":"2024-11-22T12:50:30Z"}
        """.trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8)
//        try await challengeProvider
//            .challenge(for: keyID)
        let clientDataHash = Data(SHA256.hash(data: challenge!))
        
        print("keyID string: \(keyID)")
        print("bundleId value: com.thales.appattest2")
        print("challenge value: \(challenge!.toHexString())")
        print("challengeHash string: \(clientDataHash.toHexString())")
        
        let attestVal = try await attestationProvider.attestKey(
            keyID,
            clientDataHash: clientDataHash
        )

        print("attestKey string: \(attestVal.toHexString())")
        
        let assertVal = try await attestationProvider.generateAssertion(
            keyID,
            clientDataHash: clientDataHash
        )
        
        print("generateAssertion string: \(assertVal.toHexString())")
        
        return attestVal
    }
}

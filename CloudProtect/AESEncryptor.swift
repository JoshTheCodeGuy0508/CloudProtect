import Foundation
import CryptoSwift

struct AESEncryptor {

    static func deriveKeyAndIV(password: String, salt: [UInt8]) throws -> (key: [UInt8], iv: [UInt8]) {
        let passwordBytes = Array(password.utf8)
        let derived = try PKCS5.PBKDF2(
            password: passwordBytes,
            salt: salt,
            iterations: 100_000,
            keyLength: 48,
            variant: .sha2(.sha256)
        ).calculate()
        let key = Array(derived.prefix(32))
        let iv  = Array(derived.suffix(16))
        return (key, iv)
    }

    static func encrypt(inputData: Data, password: String) throws -> Data {
        let salt: [UInt8] = (0..<16).map { _ in UInt8.random(in: 0...255) }
        let (key, iv) = try deriveKeyAndIV(password: password, salt: salt)
        let aes = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
        let inputBytes: [UInt8] = Array(inputData)
        let encrypted = try aes.encrypt(inputBytes)
        return Data(salt + encrypted)
    }

    static func decrypt(inputData: Data, password: String) throws -> Data {
        let allBytes: [UInt8] = Array(inputData)
        guard allBytes.count > 16 else { throw CryptoError.invalidData }
        let salt       = Array(allBytes.prefix(16))
        let ciphertext = Array(allBytes.dropFirst(16))
        let (key, iv) = try deriveKeyAndIV(password: password, salt: salt)
        let aes = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
        let decrypted = try aes.decrypt(ciphertext)
        return Data(decrypted)
    }

    enum CryptoError: Error {
        case invalidData
    }
}

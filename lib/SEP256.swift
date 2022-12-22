import Foundation
import CryptoKit
import Darwin

@_cdecl("CreateSEP256Key")
public func createSEP256Key(_ buffer: UnsafeMutablePointer<CChar>, _ length: UnsafeMutablePointer<CInt>) -> Bool {
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let data = key.dataRepresentation
        guard data.count <= length.pointee else {
            length.pointee = CInt(data.count)
            return false
        }
        _ = data.withUnsafeBytes {
            memcpy(buffer, $0.baseAddress, data.count)
        }
        length.pointee = CInt(data.count)
        return true
    } catch {
        return false
    }
}

@_cdecl("GetSEP256PublicKey")
public func getSEP256PublicKey(_ privateKey: UnsafeMutablePointer<CChar>,
                               _ privateKeyLength: CInt,
                               _ buffer: UnsafeMutablePointer<CChar>,
                               _ length: UnsafeMutablePointer<CInt>) -> Bool {
    do {
        let data = Data(bytesNoCopy: privateKey, count: Int(privateKeyLength), deallocator: .none)
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        let pubData = key.publicKey.x963Representation
        guard pubData.count <= length.pointee else {
            length.pointee = CInt(pubData.count)
            return false
        }
        _ = pubData.withUnsafeBytes {
            memcpy(buffer, $0.baseAddress, pubData.count)
        }
        length.pointee = CInt(pubData.count)
        return true
    } catch {
        return false
    }
}

@_cdecl("SEP256KeyAgreement")
public func seP256KeyAgreement(_ privateKey: UnsafeMutablePointer<CChar>,
                               _ privateKeyLength: CInt,
                               _ publicKey: UnsafeMutablePointer<CChar>,
                               _ publicKeyLength: CInt,
                               _ buffer: UnsafeMutablePointer<CChar>,
                               _ length: UnsafeMutablePointer<CInt>) -> Bool {
    do {
        let privateKeyData = Data(bytesNoCopy: privateKey, count: Int(privateKeyLength), deallocator: .none)
        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: privateKeyData)
        let publicKeyData = Data(bytesNoCopy: publicKey, count: Int(publicKeyLength), deallocator: .none)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        return sharedSecret.withUnsafeBytes {
            guard $0.count <= length.pointee else {
                length.pointee = CInt($0.count)
                return false
            }
            memcpy(buffer, $0.baseAddress, $0.count)
            length.pointee = CInt($0.count)
            return true
        }
    } catch {
        return false
    }
}

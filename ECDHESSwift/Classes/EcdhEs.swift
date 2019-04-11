//
//  EcdhEs.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/10.
//

import CommonCrypto
import Foundation
import JOSESwift
import Security

internal enum ECDHError: Error {
    case deriveKeyFail(reason: String)
    case invalidKeyDerivationSize
}

public typealias HashFunc = () -> Data

typealias DigestFunc = (UnsafeRawPointer?, UInt32, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?

public enum KDFHash: String {
    case SHA256 = "SHA-256"
    case SHA384 = "SHA-384"
    case SHA512 = "SHA-512"
    var digestFunc: (UnsafeRawPointer?, UInt32, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>? {
        switch self {
        case .SHA256:
            return CC_SHA256
        case .SHA384:
            return CC_SHA384
        case .SHA512:
            return CC_SHA512
        }
    }
    
    var bitLength: Int {
        switch self {
        case .SHA256:
            return 256
        case .SHA384:
            return 384
        case .SHA512:
            return 512
        }
    }
    
    var byteLength: Int {
        switch self {
        case .SHA256:
            return Int(CC_SHA256_DIGEST_LENGTH)
        case .SHA384:
            return Int(CC_SHA384_DIGEST_LENGTH)
        case .SHA512:
            return Int(CC_SHA512_DIGEST_LENGTH)
        }
    }
    
}

/**
 Derive ECDH Key Data
 
 - Parameter algorithmID: EC private JWK
 **/
public typealias OtherInfo = (
    algorithmID: Data,
    partyUInfo: Data,
    partyVInfo: Data,
    suppPubInfo: Data?,
    suppPrivInfo: Data?
)

/**
 Derive ECDH Key Data
 
 - Parameter ecPrivJwk: EC private JWK
 - Parameter ecPubJwk: EC public JWK
 - Parameter bitLen: key size
 
 - Throws: ECDHError.deriveKeyFail
 
 - Returns: Result of key exchange operation as a Data
 **/
public func deriveECDHKeyData(ecPrivJwk: ECPrivateKey, ecPubJwk: ECPublicKey, bitLen: Int = 0) throws -> Data {
    if ecPrivJwk.crv != ecPubJwk.crv {
        throw ECDHError.deriveKeyFail(reason: "Private Key curve and Public Key curve are different")
    }
    let pubKey = try ecPubJwk.converted(to: SecKey.self)
    let eprivKey = try ecPrivJwk.converted(to: SecKey.self)
    let parameters = [String: Any]()
    var error: Unmanaged<CFError>?
    
    if let derivedData = SecKeyCopyKeyExchangeResult(eprivKey, SecKeyAlgorithm.ecdhKeyExchangeStandard, pubKey, parameters as CFDictionary, &error) {
        if bitLen > 0 {
            return truncateBitLen(from: (derivedData as Data), bitLen: bitLen)
        }
        return (derivedData as Data)
    }
    if let errStr = error?.takeRetainedValue().localizedDescription {
        throw ECDHError.deriveKeyFail(reason: errStr)
    }
    throw ECDHError.deriveKeyFail(reason: "Derive Key Fail")
}

/**
 Derive ECDH-ES Key Data see https://tools.ietf.org/html/rfc7518#section-4.6
 
 - Parameter algData: "alg" JOSE Header Parameter String data
 - Parameter apuData: "apu" (Agreement PartyUInfo) JOSE Header Parameter String data
 - Parameter apvData: "apv" (Agreement PartyVInfo) JOSE Header Parameter String data
 - Parameter ecPrivKey: EC Private JWK
 - Parameter ecPubKey: EC Public JWK
 - Parameter keyDataLen: description
 
 - Throws: ECDHError.deriveKeyFail
 
 - Returns: Result of ECDH-ES key exchange Data
 **/
public func deriveECDHESKeyData(algData: Data, apuData: Data, apvData: Data, ecPrivKey: ECPrivateKey, ecPubKey: ECPublicKey, keyDataLen: Int) throws -> Data {
    let z = try deriveECDHKeyData(ecPrivJwk: ecPrivKey, ecPubJwk: ecPubKey)
    let algorithmID = prefixedBigEndenLen(from: algData)
    let partyUInfo = prefixedBigEndenLen(from: apuData)
    let partyVInfo = prefixedBigEndenLen(from: apvData)
    let suppPubInfo = intToData(value: UInt32(keyDataLen).bigEndian)
    
    return try concatKDF(KDFHash.SHA256, z, keyDataLen, algorithmID, partyUInfo, partyVInfo, suppPubInfo)
}

/**
 Concat KDF see https://tools.ietf.org/html/rfc7518#section-4.6.2
 
 - Parameter hash: HASH algorithm
 - Parameter z: The shared secret Z
 - Parameter keyDataLen: The number of bits in the desired output key.
 - Parameter algorithmID: AlgorithmID @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter partyUInfo: PartyUInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter partyVInfo: PartyVInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter suppPubInfo: SuppPubInfo @See Section 5.8.1.2 of [NIST.800-56A]
 - Parameter suppPrivInfo: SuppPrivInfo @See Section 5.8.1.2 of [NIST.800-56A]
 
 - Throws: ECDHError
 - Returns: Derived Keying Material
 **/
public func concatKDF(
    _ hash: KDFHash,
    _ z: Data,
    _ keyDataLen: Int,
    _ algorithmID: Data,
    _ partyUInfo: Data,
    _ partyVInfo: Data,
    _ suppPubInfo: Data = Data(),
    _ suppPrivInfo: Data = Data()
    ) throws -> Data {
    if keyDataLen == 0 {
        return Data()
    }
    let modLen = keyDataLen % hash.bitLength
    let reps = (keyDataLen / hash.bitLength) + (modLen > 0 ? 1 :0 )
    if reps > 0x7FFFFFFF { // according to [NIST.SP.800-56A] it should be (2^32 −1), But it will overflow Int
        throw ECDHError.invalidKeyDerivationSize
    }
    let concatedData = z + algorithmID + partyUInfo + partyVInfo + suppPubInfo + suppPrivInfo
    let hashInputLen = 4 + concatedData.count
    if hashInputLen > 0xffff {
        throw ECDHError.deriveKeyFail(reason: "Derivation parameter is more than max H input length")
    }
    let digestByteLength = hash.byteLength
    let computedDigest = {
        (data: Data) -> Data in
        var digest = [UInt8](repeating: 0, count: digestByteLength)
        _ = hash.digestFunc(Array(data), UInt32(hashInputLen), &digest)
        return Data(digest)
    }
    
    var derivedKeyingMaterial = Data()
    for i in 1..<reps {
        derivedKeyingMaterial += computedDigest(intToData(value: UInt32(i).bigEndian) + concatedData)
    }
    
    if modLen == 0 {
        derivedKeyingMaterial += computedDigest(intToData(value: UInt32(reps).bigEndian) + concatedData)
    } else {
        let digest = computedDigest(intToData(value: UInt32(reps).bigEndian) + concatedData)
        derivedKeyingMaterial += truncateBitLen(from: digest, bitLen: modLen)
    }
    return derivedKeyingMaterial
}

internal func truncateBitLen(from: Data, bitLen: Int) -> Data {
    if bitLen >= from.count * 8 {
        return from
    } else if bitLen % 8 == 0 {
        return from[0 ..< (bitLen / 8)]
    }
    let lastPos = Int(bitLen / 8)
    var result = from[0 ..< (lastPos + 1)]
    result[lastPos] = result[lastPos] & (~(0xFF >> (UInt(bitLen) % 8)))
    return result
}

internal func prefixedBigEndenLen(from: Data) -> Data {
    if from.count == 0 {
        return from
    }
    let prefix = intToData(value: UInt32(from.count).bigEndian)
    return prefix + from
}

internal func intToData<T>(value: T) -> Data where T: FixedWidthInteger {
    var int = value
    return Data(bytes: &int, count: MemoryLayout<T>.size)
}

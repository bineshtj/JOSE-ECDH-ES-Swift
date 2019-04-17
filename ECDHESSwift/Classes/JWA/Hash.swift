//
//  Hash.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import CommonCrypto

enum Hash: String {
    case SHA256 = "SHA-256"
    case SHA384 = "SHA-384"
    case SHA512 = "SHA-512"
    
    func digest(_ value: Data) -> Data {
        var digestData = [UInt8](repeating: 0, count: digestByteLength)
        _ = digestFunc(Array(value), UInt32(value.count), &digestData)
        return Data(digestData)
    }
    
    fileprivate var digestFunc: (UnsafeRawPointer?, UInt32, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>? {
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
    
    var digestByteLength: Int {
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

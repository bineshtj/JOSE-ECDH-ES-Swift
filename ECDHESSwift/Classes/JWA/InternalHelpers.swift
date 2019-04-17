//
//  InternalHelpers.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation

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
    let prefix = intToData(value: UInt32(from.count).bigEndian)
    return prefix + from
}

internal func intToData<T>(value: T) -> Data where T: FixedWidthInteger {
    var int = value
    return Data(bytes: &int, count: MemoryLayout<T>.size)
}

internal func randomBytes(size: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: size)
    guard errSecSuccess == SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) else {
        return Data(count: size)
    }
    return Data(bytes)
}

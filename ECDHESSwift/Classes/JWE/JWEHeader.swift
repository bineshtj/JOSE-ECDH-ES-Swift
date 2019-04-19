//
//  JWEHeader.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

public protocol JSONWebEncryptionHeader {
    var alg: String { get }

    var enc: String { get }

    var epk: ECPublicKey? { get }

    var apu: String? { get }

    var apv: String? { get }

    subscript(index: String) -> Any? { get }

    func jsonSerializedData() -> Data

    func allParameters() -> [String: Any]
}

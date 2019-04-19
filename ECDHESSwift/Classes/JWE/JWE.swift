//
//  EcdhEsJwe.swift
//  ECDHESSwift
//
//  Created by MFantcy on 2019/4/16.
//

import Foundation
import JOSESwift

public protocol JSONWebEncryption {
    var header: JSONWebEncryptionHeader { get }

    var encryptedKey: Data { get }

    var initializationVector: Data { get }

    var ciphertext: Data { get }

    var authenticationTag: Data { get }

    var compactSerializedString: String { get }

    var compactSerializedData: Data { get }

    var additionalAuthenticatedData: Data { get }

    func decrypt(key: JWK) throws -> Data
}

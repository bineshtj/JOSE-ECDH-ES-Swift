//
//  JWEEncryptorSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/18.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Quick
import Nimble
@testable import ECDHESSwift
import JOSESwift

class JWEEncryptorSpec: QuickSpec {
    override func spec() {
        describe("JWEEncryptor") {
            context("cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json") {
                let fixture = getCookeBookJwe5p4Fixure()
                let encryptor = EcdhEsEncryptor()
                let plaintext = fixture.input.plaintext.data(using: .utf8)!
                let staticKeyPair = fixture.input.key
                let ephemeralKeyPair = fixture.encryptingKey.epk
                let header = try! EcdhEsJweHeader(b64uData: fixture.encryptingContent.protectedB64U.data(using: .ascii)!)
                let key = Data(base64URLEncoded: fixture.generated.cek)!
                let iv = Data(base64URLEncoded: fixture.generated.iv)!
                it(fixture.title) {
                    let (resHeader, encryptedKey, resIv, ciphertext, tag)
                    = try! encryptor.encrypt(
                        plaintext: plaintext,
                        key: staticKeyPair.getPublic(),
                        header: header,
                        options: [
                            "ephemeralKeyPair": ephemeralKeyPair,
                            "key": key,
                            "iv" : iv
                        ])
                    expect(resHeader.jsonSerializedData().base64URLEncodedString()) == fixture.output.jsonFlat.protected
                    expect(encryptedKey) == Data(base64URLEncoded: fixture.encryptingKey.encryptedKey)!
                    expect(resIv) == iv
                    expect(ciphertext) == Data(base64URLEncoded: fixture.output.jsonFlat.ciphertext)!
                    expect(tag) == Data(base64URLEncoded: fixture.output.jsonFlat.tag)!
                    
                }
            }
        }
    }
}

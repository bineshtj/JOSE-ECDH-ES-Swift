//
//  EcdhJweSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/17.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import ECDHESSwift

import Quick
import Nimble

class EcdhJweSpec: QuickSpec {
    override func spec() {
        describe("cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json") {
            let fixture = getCookeBookJwe5p4Fixure()
            it("encryption should ok") {
                let plaintext = fixture.input.plaintext.data(using: .utf8)!
                let pubKey = fixture.input.key.getPublic()
                let alg = fixture.input.alg
                let enc = fixture.input.enc
                let cek = Data(base64URLEncoded: fixture.generated.cek)!
                let iv = Data(base64URLEncoded: fixture.generated.iv)!
                let eKeyPair = fixture.encryptingKey.epk
                let options: [String:Any] = ["iv": iv, "key": cek, "ephemeralKeyPair": eKeyPair]
                
                let jwe = try! EcdhEsJwe(plaintext: plaintext, pubKey: pubKey, headerDic: ["alg":alg, "enc":enc], options: options)
                let jwe2 = try! EcdhEsJwe(compactSerializedString: jwe.compactSerializedString)
                
                expect(try! jwe2.decrypt(key: fixture.input.key.getPrivate())) == plaintext
            }
        }
    }
}

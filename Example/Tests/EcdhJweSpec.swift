//
//  EcdhJweSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/17.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import ECDHESSwift
import JOSESwift
import Quick
import Nimble

class EcdhJweSpec: QuickSpec {
    override func spec() {
        describe("encrypt then decrypt") {
            for curve in [ECCurveType.P256, ECCurveType.P384, ECCurveType.P521] {
                let staticKeyPair = try! generateECKeyPair(curveType: curve)
                let plaintext = "the secret...the secret...the secret...".data(using: .utf8)!
                for alg in EcdhEsAlgorithm.allCases {
                    for enc in EncryptionAlgorithm.allCases {
                        it("curve \(curve.rawValue) \(alg.rawValue) with \(enc.rawValue) should ok") {
                            let encryptionJwe = try! EcdhEsJwe(plaintext: plaintext, pubKey: staticKeyPair.getPublic(), headerDic: ["alg": alg.rawValue, "enc": enc.rawValue])
                            let compactSerializedData = encryptionJwe.compactSerializedData
                            
                            let decryptionJwe = try! EcdhEsJwe(compactSerializedData: compactSerializedData)
                            
                            let decryptedData = try! decryptionJwe.decrypt(key: staticKeyPair.getPrivate())
                            
                            expect(decryptedData) == plaintext
                        }
                    }
                }
            }
        }
        
        describe("cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json") {
            let fixture = getCookeBookJwe5p4Fixure()
            it("decrypt should ok") {
                let plaintext = fixture.input.plaintext.data(using: .utf8)!
                let staticPrivateKey = fixture.input.key.getPrivate()
                let jwe = try! EcdhEsJwe(compactSerializedString: fixture.output.compact)
                let decripted = try! jwe.decrypt(key: staticPrivateKey)
                expect(decripted) == plaintext
            }
            
        }
    }
}

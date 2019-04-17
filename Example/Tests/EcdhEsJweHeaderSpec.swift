//
//  EcdhEsJweHeaderSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/16.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

import Quick
import Nimble
import ECDHESSwift
import JOSESwift

class EcdhEsJweHeaderSpec: QuickSpec {
    override func spec() {
        describe("normal header") {
            let jweHeaderData = """
                {
                    "alg":"ECDH-ES",
                    "enc":"A128GCM",
                    "apu":"QWxpY2U",
                    "apv":"Qm9i",
                    "epk":
                    {
                        "kty":"EC",
                        "crv":"P-256",
                        "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                        "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
                    }
                }
            """.data(using: .utf8)!
            it("from jsonData should ok") {
                let header = try! EcdhEsJweHeader(jsonData: jweHeaderData)
                expect(header.alg) == "ECDH-ES"
                expect(header.enc) == "A128GCM"
                expect(header.apu) == "QWxpY2U"
                expect(header.apv) == "Qm9i"
                expect(header.epk).to(beAKindOf(ECPublicKey.self))
                expect(header.alg).to(equal(header["alg"]! as? String))
                expect(header.enc).to(equal(header["enc"]! as? String))
                expect(header.apu).to(equal(header["apu"]! as? String))
                expect(header.apv).to(equal(header["apv"]! as? String))
                expect(header["epk"]).to(beAKindOf(ECPublicKey.self))
            }
            it("serialized should be same as input") {
                let b64url = jweHeaderData.base64URLEncodedData()
                let header = try! EcdhEsJweHeader(b64uData: b64url)
                expect(header.jsonSerializedData().base64URLEncodedData()) == b64url
            }
        }
        describe("defend parameter be setted") {
            context("alg, enc should be protected") {
                it("init unexpected type should throw") {
                    expect{ _ = try EcdhEsJweHeader(parameters: ["enc": 123, "alg": "xxx"])}.to(throwError())
                    expect{ _ = try EcdhEsJweHeader(parameters: ["enc": "bbb", "alg": false])}.to(throwError())
                    expect{ _ = try EcdhEsJweHeader(parameters: ["enc": "bbb"])}.to(throwError())
                    expect{ _ = try EcdhEsJweHeader(parameters: ["alg": "bbb"])}.to(throwError())
                    expect{ _ = try EcdhEsJweHeader(parameters: ["alg": "bbb", "enc": "bbb"])}.toNot(throwError())
                }
                it("subscript sets unexpded type should do not thing") {
                    var header = try! EcdhEsJweHeader(parameters: ["alg": "bbb", "enc": "bbb"])
                    expect(header["alg"] as? String) == "bbb"
                    header["alg"] = 123
                    expect(header["alg"] as? String) == "bbb"
                    header["alg"] = "cde"
                    expect(header["alg"] as? String) == "cde"
                    
                    expect(header["enc"] as? String) == "bbb"
                    header["enc"] = 654
                    expect(header["enc"] as? String) == "bbb"
                    header["enc"] = "bcd"
                    expect(header["enc"] as? String) == "bcd"
                }
            }
        }
    }
}

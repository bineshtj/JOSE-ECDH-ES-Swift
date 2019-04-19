//
//  EcdhJweSpec.swift
//  ECDHESSwift_Tests
//
//  Created by MFantcy on 2019/4/17.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

@testable import ECDHESSwift
import JOSESwift
import Nimble
import Quick

class EcdhJweSpec: QuickSpec {
    override func spec() {
        describe("encrypt then decrypt") {
            for curve in [ECCurveType.P256, ECCurveType.P384, ECCurveType.P521] {
                let staticKeyPair = try! generateECKeyPair(curveType: curve)
                let plaintext = """
                    永和九年，歲在癸丑，暮春之初，會于會稽山陰之蘭亭，修禊事也。群賢畢至，少長咸集。
                    此地有崇山峻嶺，茂林修竹；又有清流激湍，映帶左右，引以為流觴曲水，列坐其次。雖無絲竹管弦之盛，一觴一詠，亦足以暢敘幽情。
                    是日也，天朗氣清，惠風和暢，仰觀宇宙之大，俯察品類之盛，所以游目騁懷，足以極視聽之娛，信可樂也。
                    夫人之相與，俯仰一世，或取諸懷抱，悟言一室之內；或因寄所托，放浪形骸之外。
                    雖趣舍萬殊，靜躁不同，當其欣于所遇，暫得于己，快然自足，不知老之將至。
                    及其所之既倦，情隨事遷，感慨系之矣。
                    向之所欣，俯仰之間，已為陳跡，猶不能不以之興懷。
                    況修短隨化，終期于盡。古人云：“死生亦大矣。”豈不痛哉！(不知老之將至 一作：曾不知老之將至)
                    每覽昔人興感之由，若合一契，未嘗不臨文嗟悼，不能喻之于懷。
                    固知一死生為虛誕，齊彭殤為妄作。后之視今，亦猶今之視昔。
                    悲夫！故列敘時人，錄其所述，雖世殊事異，所以興懷，其致一也。后之覽者，亦將有感于斯文。
                    """.data(using: .utf8)!
                for alg in EcdhEsAlgorithm.allCases {
                    for enc in EncryptionAlgorithm.allCases {
                        it("curve \(curve.rawValue) \(alg.rawValue) with \(enc.rawValue) should ok") {
                            let encryptionJwe = try! EcdhEsJwe(plaintext: plaintext, pubKey: staticKeyPair.getPublic(), headerDic: ["alg": alg.rawValue, "enc": enc.rawValue])
                            let compactSerializedData = encryptionJwe.compactSerializedData

                            let decryptionJwe = try! EcdhEsJwe(compactSerializedData: compactSerializedData)

                            let decryptedData = try! decryptionJwe.decrypt(key: staticKeyPair.getPrivate())

                            expect(decryptedData) == plaintext
                        }

                        it("curve \(curve.rawValue) \(alg.rawValue) with \(enc.rawValue) data compression should ok") {
                            let encryptionJwe = try! EcdhEsJwe(plaintext: plaintext, pubKey: staticKeyPair.getPublic(), headerDic: ["alg": alg.rawValue, "enc": enc.rawValue, "zip": "DEF"])
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

        describe("encrypt and decrypt with key jwk json") {
            let pubJwk = """
              {
                "crv": "P-256",
                "kty": "EC",
                "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
                "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
              }
            """
            let privJwk = """
              {
                "crv": "P-256",
                "d": "920OCD0fW97YXbQNN-JaOtaDgbuNyVxXgKwjfXPPqv4",
                "kty": "EC",
                "x": "CQJxA68WhgU3hztigbedfLtJitDhScq3XSnXgO0FV5o",
                "y": "WFg6s36izURa733WqeoJ8zXMd7ho5OSwdWnMsEPgTEI"
              }
            """
            let plaintext = """
                紅藕香殘玉簟秋。輕解羅裳，獨上蘭舟。
                雲中誰寄錦書來？雁字回時，月滿西樓。

                花自飄零水自流。一種相思，兩處閒愁。
                此情無計可消除，纔下眉頭，卻上心頭。
                """.data(using: .utf8)!

            let encryptionJwe = try! EcdhEsJwe(plaintext: plaintext, pubKeyJwkJson: pubJwk, headerDic: ["alg": "ECDH-ES+A256KW", "enc": "A256GCM"])

            let compactSerializedString = encryptionJwe.compactSerializedString
            
            let decryptionJwe = try! EcdhEsJwe(compactSerializedString: compactSerializedString)

            let decrypted = try! decryptionJwe.decrypt(privKeyJwkJson: privJwk)

            expect(decrypted) == plaintext
        }
    }
}

//
//  EcJwkTests.swift
//  Jose_Example
//
//  Created by MFantcy on 2019/4/9.
//

import XCTest
import JOSESwift
@testable import ECDHESSwift

class EcJwkTests: XCTestCase {
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testGenerateP256KeyPaire() {
        XCTAssertNoThrow(try generateECKeyPair(curveType: ECCurveType.P256)) {
            (ecKeyPair: ECKeyPair) in
            XCTAssertEqual(ecKeyPair.crv, ECCurveType.P256)
        }
        XCTAssertNoThrow(try generateECKeyPair(curveType: ECCurveType.P384)) {
            (ecKeyPair: ECKeyPair) in
            XCTAssertEqual(ecKeyPair.crv.rawValue as String, "P-384")
        }
        XCTAssertNoThrow(try generateECKeyPair(curveType: ECCurveType.P256)) {
            (ecKeyPair: ECKeyPair) in
            XCTAssertEqual(ecKeyPair.crv, ECCurveType.P256)
        }
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
}

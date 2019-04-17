//
//  TestingUtils.swift
//  ECDHESSwift_Tests
//
//  Created by Jack Zhu on 2019/4/11.
//

import Foundation
import XCTest

public func XCTAssertNoThrow<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #file, line: UInt = #line, also validateResult: (T) -> Void) {
    func executeAndAssignResult(_ expression: @autoclosure () throws -> T, to: inout T?) rethrows {
        to = try expression()
    }
    var result: T?
    XCTAssertNoThrow(try executeAndAssignResult(expression, to: &result), message, file: file, line: line)
    if let r = result {
        validateResult(r)
    }
}

extension Data {
    func numberString() -> String {
        let format =  "%d"
        return map { String(format: format, $0) }.joined(separator: ", ")
    }
    init(hex: String) {
        let hexAlphabet = [Character]("0123456789abcdef")
        var lowercaseHex = [Character](hex.lowercased().replacingOccurrences(of: " ", with: ""))
        lowercaseHex = [Character]([Character](lowercaseHex.count & 2 == 1 ? "0":"") + lowercaseHex)
        var res = [UInt8]()
        var c: UInt8 = 0
        for idx in 0 ..< lowercaseHex.count {
            guard let num = hexAlphabet.index(of: lowercaseHex[idx]) else {
                self.init()
                return
            }
            c = (c * 16) + UInt8(num)
            if idx % 2 == 1 {
                res.append(c)
                c = 0
            }
        }
        self.init(res)
    }
}


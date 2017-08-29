//
//  ASN1DecoderTests.swift
//  ASN1DecoderTests
//
//  Copyright © 2017 Filippo Maguolo.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.


import XCTest
@testable import ASN1Decoder

class ASN1DecoderTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        
        var serialNumber = ""
        var subject = ""
        
        if let certData = Data(base64Encoded: cert) {
            do {
                let x509 = try X509Certificate(data: certData)
                
                serialNumber = x509.serialNumber?.hexEncodedString() ?? ""
                
                subject = x509.subjectDistinguishedName ?? ""
                
            } catch {
                print(error)
            }
        }
        
        XCTAssertEqual(serialNumber, "59A2F004")
        
        XCTAssertEqual(subject, "CN=John Smith, L=New York, C=US, E=john@mail.com")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    
    let cert =
        "MIIDMzCCAhugAwIBAgIEWaLwBDANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJV" +
        "UzERMA8GA1UEBwwITmV3IFlvcmsxHDAaBgkqhkiG9w0BCQEWDWpvaG5AbWFpbC5j" +
        "b20xEzARBgNVBAMMCkpvaG4gU21pdGgwHhcNMTcwODI3MTYxNTAwWhcNMTgwODI3" +
        "MTYxNTAwWjBTMQswCQYDVQQGEwJVUzERMA8GA1UEBwwITmV3IFlvcmsxHDAaBgkq" +
        "hkiG9w0BCQEWDWpvaG5AbWFpbC5jb20xEzARBgNVBAMMCkpvaG4gU21pdGgwggEi" +
        "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHc/RdKvcz+Sakwykuq/+mJZCQ" +
        "ELYYk3ceVrYOwefaFLent4JU+/ATm+CQFXqyiQM1BTtXUwA3gG0sCufMUG5wkHN0" +
        "86KwclYhzPRZNGtLW2QshvvaN2wE4HxbFJ/DUUHPGuIlzewfecg/ZG9CwGeb/HQ4" +
        "Qx+BI/U7JXykyNHFwMQrS5hGmvLH7MxSYiqt8X2VZ7vabxdqnvpufK34SyVQXkfR" +
        "twLNj7GO807HNQ5EGFw1hxJN3tBXG4z+1eq4rgy1RJY7c6ntkzOczrqw7Ut4OUmC" +
        "RjAEggqPrG6R94D2f8vgEXB42TPSEKWwHi6/RAEZ1WO5YsDmLHVNxp8FvThVAgMB" +
        "AAGjDzANMAsGA1UdDwQEAwIGQDANBgkqhkiG9w0BAQsFAAOCAQEAhlIaMaE9YTJU" +
        "uSCy0LAd+nHzuTdokgDCXdT75KtsiNtQHQIDtLhdJGYUzlWUwY8SQWytvJORKi3q" +
        "rA45oLwSJjVY4hZuNcaWleDumnHc4rbK9o6GJhEk/T49Vrc9q4CNX0/siPBsHwXd" +
        "rqrLOR00yfrMYCPAUCryPbdx/IPbo8Z3kvlQHn8cqOjgqdwuy7PTMIMz6sCsBcV0" +
        "OeAp80GDRAHpjB3qYhzhebiRiM+Bbqva6f4bxNmDNQtL0jt0a8KeyQrFNdAhgjYk" +
        "AKTucThCu1laJKGKABK90dMoLtbJFxfRhjzmjX9TJGYJgCnRNDDnXpVUOspv2YeH" +
        "vC9gOdRhaA=="
    
}


extension Data {
    
    func hexEncodedString(separation: String = "") -> String {
        return reduce("") {$0 + String(format: "%02X\(separation)", $1)}
    }

}

//
//  ASN1DecoderAlternativeName.swift
//  ASN1DecoderTests
//
//  Copyright © 2020 Filippo Maguolo.
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

class ASN1DecoderAlternativeNames: XCTestCase {

    func testDecodingAlternativeNames() {
        var subjectAlternativeNames = [String]()
        
        let certificateData = samplePEMcertificate.data(using: .utf8)!
        do {
            let x509 = try X509Certificate(data: certificateData)
            subjectAlternativeNames = x509.subjectAlternativeNames
        } catch {
            print(error)
        }
        XCTAssertTrue(subjectAlternativeNames.contains("dns.name"))
        XCTAssertTrue(subjectAlternativeNames.contains("192.168.0.1"))
        XCTAssertTrue(subjectAlternativeNames.contains("upn.name"))
        XCTAssertTrue(subjectAlternativeNames.contains("1.2.3.4.5"))
        XCTAssertTrue(subjectAlternativeNames.contains("rfc.822.name"))
        XCTAssertTrue(subjectAlternativeNames.contains("uri.name"))
        XCTAssertTrue(subjectAlternativeNames.contains("CN=common_name, OU=dev_world"))
    }
    
    let samplePEMcertificate =
        """
        -----BEGIN CERTIFICATE-----
        MIIDLzCCAhegAwIBAgIEX4galDANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtj
        b21tb25fbmFtZTAeFw0yMDEwMTUwOTQ3MDBaFw0yMTEwMTUwOTQ3MDBaMBYxFDAS
        BgNVBAMMC2NvbW1vbl9uYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
        AQEAo9Uxc9OflevRAjXrAdT+5tmi4CBqc0wLPnx9m08HpTN1w1z+GwbCndPKNYgW
        N3DyjIjpiOa9IMif4P8p8L2Kb+76gCoV018fXs/bDYLFc/uiiYKIGZ6GU8COOgcJ
        XVfz6I/yv7Ruu5oSEyRLkW7hN4cSfN7b0sEbC3JUR0L5WNraIIQcOAmhRBk09oXM
        0Ai2bIC5GR8Id//NDg7FTGIvQ75fIEaIiOxtNgB2bkibHARtHCGqmqkf3XRVNrhO
        ybg7808I9HYljDxNOI9UxQ3qyPRKLnQSwcrjBepF+GYAKrBbTqfhwk1+iTTmKM4f
        iWH9V0e4mPjXQXl6s3TMFZQTRwIDAQABo4GEMIGBMH8GA1UdEQR4MHakLDAqMRIw
        EAYDVQQLDAlkZXZfd29ybGQxFDASBgNVBAMMC2NvbW1vbl9uYW1lgghkbnMubmFt
        ZYcEwKgAAaAYBgorBgEEAYI3FAIDoAoMCHVwbi5uYW1liAQqAwQFgQxyZmMuODIy
        Lm5hbWWGCHVyaS5uYW1lMA0GCSqGSIb3DQEBCwUAA4IBAQCdH9e5fhk2nDnMiIUI
        E5XMLjLrNF4sGPB9Jh3FQTa8DD320aR8STeYUZr5GqcgZ1IkBVNeVX1zhUJp+fAw
        8NfSsAQGVQvbSQ6nzfpdCoCgl+s4khKg10IMW6p2BULpX8fxW0JFUgAMwKJfkNxC
        9kFXpMqazFoSy+dpJkSc+ZlElCvYx7mKycf/30OHWWNqdTBkFehUTTpiYSH9Uc3V
        ikCrKEikRxNwVYySCcWQsxARUYgXnH5IUTj1Or5awEWA72m363zb87iNlvYlgc2c
        tIrtDCLmWxFejP0oAfdzgfineN4XQwJGBlR2/OMCkQJxynyq+TfgXhtVmvmzPnZx
        D4cy
        -----END CERTIFICATE-----
        """
}

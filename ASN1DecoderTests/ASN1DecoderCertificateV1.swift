//
//  ASN1DecoderExtensions.swift
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

class ASN1DecoderCertificateV1: XCTestCase {
    
    func getCertificate() throws -> X509Certificate {
        let certificateData = samplePEMcertificate.data(using: .utf8)!
        return try X509Certificate(data: certificateData)
    }

    func testVersion1() {
        do {
            let x509 = try getCertificate()
            XCTAssertEqual(x509.version, 1)
            XCTAssertEqual(x509.subjectDistinguishedName, "C=NL, O=development, CN=localhost")
            XCTAssertEqual(x509.publicKey?.algName, "rsaEncryption")
        } catch {
            XCTFail("\(error)")
        }
    }
    
    let samplePEMcertificate = """
        -----BEGIN CERTIFICATE-----
        MIIC6jCCAdICCQCII7IrJYChQDANBgkqhkiG9w0BAQsFADA3MQswCQYDVQQGEwJO
        TDEUMBIGA1UECgwLZGV2ZWxvcG1lbnQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0y
        MTA2MjgxMDI5MjdaFw0yMjA2MjgxMDI5MjdaMDcxCzAJBgNVBAYTAk5MMRQwEgYD
        VQQKDAtkZXZlbG9wbWVudDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG
        9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtHT7F6AIFWuE+RqXXXMsm/LwWapsZzBBkSJ/
        xWskFPM7EEkRXMoFRcE5DRxqhY2SUVc55JYMCITIL1IyavVe6eDk1cjf4Iiw09Tj
        M2vbn/sZI+ACcK8lQ29196753OqmYPKL30vZ7NYG85/1aNBeI4ZEgfD7nyExTw69
        2VgRJok3LBiJkjfmml2EdGBTeG//yEGuvOkUbu0KOzi/eax/jNsn2V5ABEnblVIU
        mENeWoKQeP81gBZeZ3tvAp0eruNXdjQbxjz3SODYPJwY319sxF7y/LeRROmV+ZAw
        6IH5rrKa7yqkMk5oNVSJ28IiZTRyp3NwKZtTo+q3ae+ueAmZewIDAQABMA0GCSqG
        SIb3DQEBCwUAA4IBAQBBNivz9HK3GU6Ey5zj6xpKEjq3CdUNHOoPMirBpdn3PT/J
        T4qHKzWxFup0hhEpcHKyA42SkvqA6uUqV2CsaNR9tlBxzsr1V/z23h16jXarTMOl
        XymCgFrvHOhsRF5qxywIH338oMhbM0B+N0huFpRRx5li86bIWpmg2zm82gVWuFGs
        cFabGVNEQS87vlCVr2/fLwKhemv1CVw9ZrkHU3BPA08r8Ki6f30ByqiYvu2xC7a9
        dHTz8vBLPJO0xSKwMj4Dc0qTKtG96i+j+EUdUxhhr1VKZdL5geuvB0UUx/aNItnD
        b53SqLt8wT0gDWIn4pNDgyONusSfSBHdOjsE8oqf
        -----END CERTIFICATE-----
        """
   
}

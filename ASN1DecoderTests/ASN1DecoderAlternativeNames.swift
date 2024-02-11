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
        do {
            let x509 = try X509Certificate(data: samplePEMcertificateData)
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
        XCTAssertTrue(subjectAlternativeNames.contains("OU=dev_world, CN=common_name"))
    }
    
    let samplePEMcertificateData =
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
        """.data(using: .utf8)!
    
    func testDecodingAlternativeNamesIPv6() throws {
        let x509 = try X509Certificate(data: samplePEMcertificateDataIPv6)
        let subjectAlternativeNames = x509.subjectAlternativeNames
        XCTAssertTrue(subjectAlternativeNames.contains("1.2.3.4"))
        XCTAssertTrue(subjectAlternativeNames.contains("10.150.200.250"))
        XCTAssertTrue(subjectAlternativeNames.contains("2001:4860:4860:0:0:0:0:64"))
        XCTAssertTrue(subjectAlternativeNames.contains("2620:100:6040:18:0:0:a27d:f812"))
    }
    
    let samplePEMcertificateDataIPv6 = """
        -----BEGIN CERTIFICATE-----
        MIIC0zCCAbugAwIBAgIEZclRLDANBgkqhkiG9w0BAQsFADAMMQowCAYDVQQDDAFB
        MB4XDTI0MDIxMTIyNTg1MloXDTI1MDIxMDIyNTg1MlowDDEKMAgGA1UEAwwBQTCC
        ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANu3sr9zJbJeQ0uvx0s3K6Ws
        LPy6C7iud7W+RvTXFBTK2ZA+tVk81uzW6xQdbGrQYUV7LvDozbv8CEdf1SuUvhMN
        T4N7YTP6Od2qKjfXTSCpUgE2EYF45LqRZAcTyZ+8QRpYgeKTLObnIJzikOghToKN
        9Q74jB7WIO3sb3QeXGTlTmHgERVrsFNy3g6eJ1cFCM/1ghB1Ln6ucgh7AH+zL2Bl
        +mOG2/sMAFwJxydI37u3Ua6TW73a5PzNftDsz2pAWBy65nHYDO1IibLdWT1nizz1
        AG1qMzfDUA6OXs65XhQI8PJzF844CPmoF0YKARzk+0zBCiJadC7RLXo0fS7zxDMC
        AwEAAaM9MDswOQYDVR0RBDIwMIcEAQIDBIcECpbI+ocQIAFIYEhgAAAAAAAAAAAA
        ZIcQJiABAGBAABgAAAAAon34EjANBgkqhkiG9w0BAQsFAAOCAQEAIYFr0B2TswUM
        5eD4KWbC390E+6CklGS3xcFTybXjiXWjyMS1116+jENgLJ3ZDQhVIgEPuLRiQbym
        0M83e4MdzqgClno8wMHBIYexQh89Ci7/Lr/5YJUnC/uEpbtEGFBzbJYpQFhVLgRV
        +vhb5It38fBEM2wfrH652oBecsznc1z5iTNW+h4OnxMd6CIPKOPsFyX2CSyWiYdS
        za2e5vkcu62kqQ/1F9RyG47xusH/6hWwtXz5eaFmoFyk/rjTyhrfR1Dc/xfQQOdM
        ta/QiONVU30kkSfIpidpiP6+ORHx6AbglB1v+jAVpKAPura4T3Yjov7zE7x5zEOL
        NnOQ2YQKSA==
        -----END CERTIFICATE-----
        """.data(using: .utf8)!
    
    
    // MARK: - Test Subject with multiple domain component
    
    func testDoubleDomain() {
        do {
            let x509 = try X509Certificate(data: samplePEMcertificateData2)
            let dc = x509.subject(oid: .domainComponent)
            XCTAssertEqual(dc, ["domain2", "domain1"])
        } catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    let samplePEMcertificateData2 =
        """
        -----BEGIN CERTIFICATE-----
        MIIBcjCCARigAwIBAgIEX6WPwDAKBggqhkjOPQQDAjBBMRcwFQYKCZImiZPyLGQB
        GRYHZG9tYWluMjEXMBUGCgmSJomT8ixkARkWB2RvbWFpbjExDTALBgNVBAMMBG5h
        bWUwHhcNMjAxMTA2MTgwMjQwWhcNMjExMTA2MTgwMjQwWjBBMRcwFQYKCZImiZPy
        LGQBGRYHZG9tYWluMjEXMBUGCgmSJomT8ixkARkWB2RvbWFpbjExDTALBgNVBAMM
        BG5hbWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATCCOGTRqbJ3tQQxl2gVsY+
        Pk4VvAkW+D6lDSpDLadEBOlRirr3WrTsKPVTtsKA5YIt1e/zBxl9g5OgTJq8ktjI
        MAoGCCqGSM49BAMCA0gAMEUCIB5Br1e3dUwbTYubxHkDHDJqmG48sbdMZbuB19oD
        wThoAiEA0eEpfby8LRQcFlybk0LKyRrl1m4DGyMfgN/5bJaN9zU=
        -----END CERTIFICATE-----
        """.data(using: .utf8)!
}

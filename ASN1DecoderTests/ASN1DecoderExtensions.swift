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

class ASN1DecoderX509Extensions: XCTestCase {
    
    func getCertificate() throws -> X509Certificate {
        let certificateData = samplePEMcertificate.data(using: .utf8)!
        return try X509Certificate(data: certificateData)
    }

    func testAuthorityKeyIdentifier() {
        do {
            let x509 = try getCertificate()

            if let ext = x509.extensionObject(oid: .authorityKeyIdentifier) as? X509Certificate.AuthorityKeyIdentifierExtension {
                XCTAssertEqual(ext.keyIdentifier?.hexEncodedString(), "76028647F1F6A396C9BFD22D8E300E28398C588B")
                XCTAssertEqual(ext.serialNumber?.hexEncodedString(), "5FA31045")
                
                let certificateIssuer = ext.certificateIssuer
                XCTAssertTrue(certificateIssuer?.contains("www.hostname.net") == true)
                XCTAssertTrue(certificateIssuer?.contains("192.168.1.99") == true)
                XCTAssertTrue(certificateIssuer?.contains("CN=EXTENSION TEST") == true)
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testBasicConstraint() {
        do {
            let x509 = try getCertificate()
            
            if let ext = x509.extensionObject(oid: .basicConstraints) as? X509Certificate.BasicConstraintExtension {
                XCTAssertEqual(ext.isCA, true)
                XCTAssertEqual(ext.pathLenConstraint, 3)
            } else {
                XCTFail("Extension not found")
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testExtKeyUsage() {
        do {
            let x509 = try getCertificate()
            let extKeyUsage = x509.extendedKeyUsage
            XCTAssert(extKeyUsage.contains("1.3.6.1.5.5.7.3.2")) // TLS Web Client Authentication
            XCTAssert(extKeyUsage.contains("1.3.6.1.5.5.7.3.4")) // E-mail Protection
            XCTAssert(extKeyUsage.contains("1.3.6.1.4.1.311.10.3.4")) // Encrypted File System
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testSubjectKeyIdentifier() {
        do {
            let x509 = try getCertificate()
            
            if let ext = x509.extensionObject(oid: .subjectKeyIdentifier), let value = ext.value as? Data {
                XCTAssertEqual(value.hexEncodedString(), "76028647F1F6A396C9BFD22D8E300E28398C588B")
            } else {
                XCTFail("Extension not found")
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testCertificatePolicies() {
        do {
            let certificateData = samplePEMcertificateApple.data(using: .utf8)!
            let x509 = try X509Certificate(data: certificateData)
            
            if let ext = x509.extensionObject(oid: .certificatePolicies) as? X509Certificate.CertificatePoliciesExtension,
               let policies = ext.policies {

                XCTAssertEqual(policies[0].oid, "2.16.840.1.114412.2.1")
                XCTAssertEqual(policies[0].qualifiers?[0].oid, "1.3.6.1.5.5.7.2.1")
                XCTAssertEqual(policies[0].qualifiers?[0].value, "https://www.digicert.com/CPS")
                
                XCTAssertEqual(policies[1].oid, "2.23.140.1.1")
                
            } else {
                XCTFail("Extension not found")
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testCertificateCRL() {
        do {
            let certificateData = samplePEMcertificateApple.data(using: .utf8)!
            let x509 = try X509Certificate(data: certificateData)
            
            if let ext = x509.extensionObject(oid: .cRLDistributionPoints) as? X509Certificate.CRLDistributionPointsExtension,
               let crls = ext.crls {
                
                XCTAssertTrue(crls.contains("http://crl3.digicert.com/DigiCertSHA2ExtendedValidationServerCA-3.crl"))
                XCTAssertTrue(crls.contains("http://crl4.digicert.com/DigiCertSHA2ExtendedValidationServerCA-3.crl"))

            } else {
                XCTFail("Extension not found")
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    func testAuthorityInfoAccess() {
        do {
            let certificateData = samplePEMcertificateApple.data(using: .utf8)!
            let x509 = try X509Certificate(data: certificateData)
            
            if let ext = x509.extensionObject(oid: .authorityInfoAccess) as? X509Certificate.AuthorityInfoAccessExtension,
               let infoAccess = ext.infoAccess {
                
                XCTAssertEqual(infoAccess[0].method, "1.3.6.1.5.5.7.48.1")
                XCTAssertEqual(infoAccess[0].location, "http://ocsp.digicert.com")
                
                XCTAssertEqual(infoAccess[1].method, "1.3.6.1.5.5.7.48.2")
                XCTAssertEqual(infoAccess[1].location, "http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA-3.crt")
                
            } else {
                XCTFail("Extension not found")
            }
        } catch {
            XCTFail("\(error)")
        }
    }
    
    let samplePEMcertificate = """
        -----BEGIN CERTIFICATE-----
        MIIDejCCAmKgAwIBAgIEX6MQRTANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDDA5F
        WFRFTlNJT04gVEVTVDAeFw0yMDExMDQyMDM0MTNaFw0yMTExMDQyMDM0MTNaMBkx
        FzAVBgNVBAMMDkVYVEVOU0lPTiBURVNUMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
        MIIBCgKCAQEA0Q9U9Qd7ELpyx46zI6tL7UtIGDv48BaDKPO7JkcOyXE2OunO+/Rd
        U7nrJP4t7KVoFDYAbzHfy3ViaCN/zzcHUQV5VLtg3ydaM3ruJ8lWZjj1nsH2hPxl
        Rth6BttV64mRSUGc4w+OEoj/WMrErCS6uXs0Xjd/1+6h3MUnBua5pwhh59Wj9dCo
        8Dn8gcsnFHy/GVMSfwSdSxWpuMfyPNfzQ4jffoneZv/xYpeYqFYdqs5cODqPsfqr
        t8+T8Xh30pbDAVwQ0t7EMb+IH5oXIkujEDx+FViyqya/H+E5IXuMecFshD4Rebp5
        f/9eE9Ct7BbfEeBOglzyYxB118+CswtcIwIDAQABo4HJMIHGMA8GA1UdEwQIMAYB
        Af8CAQMwXAYDVR0jBFUwU4AUdgKGR/H2o5bJv9ItjjAOKDmMWIuhNaQbMBkxFzAV
        BgNVBAMMDkVYVEVOU0lPTiBURVNUghB3d3cuaG9zdG5hbWUubmV0hwTAqAFjggRf
        oxBFMB0GA1UdDgQWBBR2AoZH8fajlsm/0i2OMA4oOYxYizApBgNVHSUEIjAgBggr
        BgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwQwCwYDVR0PBAQDAgEGMA0GCSqG
        SIb3DQEBCwUAA4IBAQBBVNtPF++n2KnL3sdezfx0BN1Thzz/k2D/amUnNcMNrUUj
        T4k0Nu6ZQZPxnjH8VNAel7eFpRaLOS/zS9B63695lFnOOzJSKec2i0uyl9hRAMf5
        HCoowRijyM9KfIHF8UQ2TSBJkL0Dbdhw6Yszq7JcGUj0g4mX/6c9MlsZFRfJ6S6I
        mavDHwPsTf6Abz9em4rMF4HVoDpoky/srDh5JsFHZ37uiWtlyUpk87UgNZI+1xA+
        3wCZU9yLMOYO7a2j7mLFSJobrN2BZPZYoFjto38XOkPpZxJSUWOPHekig1bH6Nwy
        EBbHNd47ucLIF9f7UWBbBxnl1tjp8VVqX6IBsYuS
        -----END CERTIFICATE-----
        """
    
    let samplePEMcertificateApple = """
        -----BEGIN CERTIFICATE-----
        MIIIBTCCBu2gAwIBAgIQA44/ngnX7cexgD90p0w1qzANBgkqhkiG9w0BAQsFADB5
        MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xGTAXBgNVBAsT
        EHd3dy5kaWdpY2VydC5jb20xNjA0BgNVBAMTLURpZ2lDZXJ0IFNIQTIgRXh0ZW5k
        ZWQgVmFsaWRhdGlvbiBTZXJ2ZXIgQ0EtMzAeFw0yMDEwMDcwMDAwMDBaFw0yMTEw
        MDgxMjAwMDBaMIHHMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjETMBEG
        CysGAQQBgjc8AgEDEwJVUzEbMBkGCysGAQQBgjc8AgECEwpDYWxpZm9ybmlhMREw
        DwYDVQQFEwhDMDgwNjU5MjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3Ju
        aWExEjAQBgNVBAcTCUN1cGVydGlubzETMBEGA1UEChMKQXBwbGUgSW5jLjEWMBQG
        A1UEAxMNd3d3LmFwcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
        ggEBAMobHCF4FT1Az6N5P53PslOrqUH/PgahKWmKBEae+8QNVnrK5oDnr8bAv4tg
        ccqa6HYMBsibd7jzG+p+5zqEy6OIpZMEP2lmd8+uBtHZ4RAIeuAkmOdWlw9zaHtN
        aUYoJv8FgQzA2vwhcYFlmjnJ6Wg2NgJfgYC3fopb/jTQznYt2Ys+1BPA7OsPLHet
        Hnsg9tqSmP2J86fLUxYusLlivsjDKEDPjFxhd4+SPS8j8gqrZYIiuJjOusgAleRn
        NG525dHTLVGRvO/AyN74e8xGRQB22cswMelW/Q5o9Db5G1+IYWKPYKjeQ3tcwRVz
        1AYSboWbUJwkv1/89GiVZ9W/RHECAwEAAaOCBDgwggQ0MB8GA1UdIwQYMBaAFM+F
        8bw4GHg6VTP0VsrAaa13bruTMB0GA1UdDgQWBBQmH7tn0rlB7VcS548sc00Xi2tw
        jjA8BgNVHREENTAzghBpbWFnZXMuYXBwbGUuY29tgg13d3cuYXBwbGUuY29tghB3
        d3cuYXBwbGUuY29tLmNuMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF
        BQcDAQYIKwYBBQUHAwIwgaUGA1UdHwSBnTCBmjBLoEmgR4ZFaHR0cDovL2NybDMu
        ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkV4dGVuZGVkVmFsaWRhdGlvblNlcnZl
        ckNBLTMuY3JsMEugSaBHhkVodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
        cnRTSEEyRXh0ZW5kZWRWYWxpZGF0aW9uU2VydmVyQ0EtMy5jcmwwSwYDVR0gBEQw
        QjA3BglghkgBhv1sAgEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl
        cnQuY29tL0NQUzAHBgVngQwBATCBigYIKwYBBQUHAQEEfjB8MCQGCCsGAQUFBzAB
        hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wVAYIKwYBBQUHMAKGSGh0dHA6Ly9j
        YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJFeHRlbmRlZFZhbGlkYXRp
        b25TZXJ2ZXJDQS0zLmNydDAJBgNVHRMEAjAAMIIB9gYKKwYBBAHWeQIEAgSCAeYE
        ggHiAeAAdwD2XJQv0XcwIhRUGAgwlFaO400TGTO/3wwvIAvMTvFk4wAAAXUE5RIw
        AAAEAwBIMEYCIQDfwCPGlYS5Fzl5E9qSJfXEJZKk3Bocy3gRZ3VnSetQ9wIhAJTV
        W7NpwxMvgje6f3Bl4pD/8LONvdNOfQhA/RRf/mZgAHUAXNxDkv7mq0VEsV6a1Fbm
        EDf71fpH3KFzlLJe5vbHDsoAAAF1BOUShAAABAMARjBEAiBym6EmF1g6CDmqOaKZ
        LiOpKJ310wVgWfezVSZoqZCUTQIgbMkp3ZqwIJlxECUiFNCcWvOvXDnRjTmZRNnU
        gl9wFj8AdgBWFAaaL9fC7NP14b1Esj7HRna5vJkRXMDvlJhV1onQ3QAAAXUE5RQW
        AAAEAwBHMEUCIQDtvAk0Fs6QOodDRWXG8pwviOAD0A3P8MrepljlmvCC+AIgaYPc
        dA2gwQbMR+muIHIw6zzpDE2rgBYUmmirGfGXGq8AdgCkuQmQtBhYFIe7E6LMZ3AK
        PDWYBPkb37jjd80OyA3cEAAAAXUE5RThAAAEAwBHMEUCIQDVJYiGuX96WaI2ry/P
        uChTJsmpiTxPwJItHL0YMJ+HmQIga60LicX5sIxA7jVWLe1skZQvA8SM8dTY9mjf
        5qpP9U8wDQYJKoZIhvcNAQELBQADggEBACLAg6hBZGjc2m3vB0YyMlclnv5dQ0vy
        F8JfHobkrFQ7O+mW35LiDY/ZIF9KBLGY5eOtHSYX8+Ktt1bcRilwq9Vjip80Atb4
        Wpzq9tM6zFx+oxVGv1YsOWdCir94838tP0d0ILqoyqUWVu6HgyJBu3ZEABaSZcIx
        4TjJ9LhOtzyO44mcHqgNXiA7IdK3TPs39iAmVx3+3PQmwjbGGjKgR0rORIGUuCa6
        YVqR0ad1wWG4M24HgTR/+d40C4JNVY3FFptUvCCw4yD5Jzk2duFsAmC9bZxpTbzc
        hoOQIW3CEt8hUquiqBBvOv+7YI3JrMHBsLt9T44YYiKC+XkFnh7yG9E=
        -----END CERTIFICATE-----
        """
}

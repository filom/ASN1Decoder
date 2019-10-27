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

    func testDecodingPEM() throws {
        let x509 = try X509Certificate(data: certPEMData)
        XCTAssertEqual(x509.serialNumber?.hexEncodedString(),
                       "0836BAA2556864172078584638D85C34")
        XCTAssertEqual(x509.subjectDistinguishedName,
                       "CN=www.digicert.com, SERIALNUMBER=5299537-0142, OU=SRE, O=\"DigiCert, Inc.\", L=Lehi, ST=Utah, C=US")
        
        XCTAssertEqual(x509.subject(dn:.commonName), "www.digicert.com")
        XCTAssertEqual(x509.subject(dn:.serialNumber), "5299537-0142")
        XCTAssertEqual(x509.subject(dn:.organizationalUnitName), "SRE")
        XCTAssertEqual(x509.subject(dn:.organizationName), "DigiCert, Inc.")
        XCTAssertEqual(x509.subject(dn:.localityName), "Lehi")
        XCTAssertEqual(x509.subject(dn:.stateOrProvinceName), "Utah")
        XCTAssertEqual(x509.subject(dn:.countryName), "US")
        
        XCTAssertEqual(x509.issuerDistinguishedName,"CN=DigiCert SHA2 Extended Validation Server CA, OU=www.digicert.com, O=DigiCert Inc, C=US")
        XCTAssertEqual(x509.issuer(dn:.commonName), "DigiCert SHA2 Extended Validation Server CA")
        XCTAssertEqual(x509.issuer(dn:.organizationalUnitName), "www.digicert.com")
        XCTAssertEqual(x509.issuer(dn:.organizationName), "DigiCert Inc")
        XCTAssertEqual(x509.issuer(dn:.countryName), "US")
    }

    func testDecoding() {
        var serialNumber = ""
        var subject = ""
        var subjectCommonName = ""
        var issuer = ""
        var issuerEMail = ""
        
        if let certData = Data(base64Encoded: cert) {
            do {
                let x509 = try X509Certificate(data: certData)
                
                serialNumber = x509.serialNumber?.hexEncodedString() ?? ""
                
                subject = x509.subjectDistinguishedName ?? ""
                
                subjectCommonName = x509.subject(dn:.commonName) ?? ""
                
                issuer = x509.issuerDistinguishedName ?? ""
                issuerEMail = x509.issuer(dn: .email) ?? ""
                
            } catch {
                print(error)
            }
        }
        
        XCTAssertEqual(serialNumber, "59A2F004")
        
        XCTAssertEqual(subject, "CN=John Smith, L=New York, C=US, E=john@mail.com")
        XCTAssertEqual(subjectCommonName, "John Smith")
        
        XCTAssertEqual(issuer, "CN=John Smith, L=New York, C=US, E=john@mail.com")
        XCTAssertEqual(issuerEMail, "john@mail.com")
        
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

    let certPEM = """
-----BEGIN CERTIFICATE-----
MIIItzCCB5+gAwIBAgIQCDa6olVoZBcgeFhGONhcNDANBgkqhkiG9w0BAQsFADB1
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE4MDYyNjAwMDAwMFoXDTIwMDYzMDEy
MDAwMFowgc8xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB
BAGCNzwCAQMTAlVTMRUwEwYLKwYBBAGCNzwCAQITBFV0YWgxFTATBgNVBAUTDDUy
OTk1MzctMDE0MjELMAkGA1UEBhMCVVMxDTALBgNVBAgTBFV0YWgxDTALBgNVBAcT
BExlaGkxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMQwwCgYDVQQLEwNTUkUxGTAX
BgNVBAMTEHd3dy5kaWdpY2VydC5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
ggIKAoICAQDOn4XKOTAwt/aYabScEF1QOyVj0OVo1NmlyizWNZWyPg0pi53ggUoE
98CeNUkz+6scEYqWNY6l3qKB56pJJIqNQmo9NoWO8k2G/jTIjFFGqNWYIq23i4+H
qaXi1/H/aWFgazk1qkyyAOQQA/p56bG9m5Ok/IBM/BZnLqVJLGJOx9ihgG1dI9Dr
6vap+8QaPRau3t9sEd2cxe4Ix7gLdaYG3vxsYf3BycKTSKtyrbkX1Qy0dsSxy+GC
M2ETxE1gMa7vRomQ/ZoZo8Ib55kFp6lIT6UOOkkdyiJdpWPXIZZlsZR5wkegWDsJ
P7Xv7nE0WMkY1+05iNYtrzZRhhlnBw2AoMGNI+tsBXLQKeZfWFmU30bhkzX99pmv
IYJ3f1fQGLao44nQEjdknIvpm0HMgvagYCnQVnnhJStzyYz324flWLPSp57OQeNM
tr6O5W0HdWyhUZU+D4R6wObYQMZ5biYjRhtAQjMg8EVQEfZzEdr0WGO5JRHLHyot
8tErXM9DiF5cCbzfcjeuoik2SHW+vbuPagMiHTM9+3lr0oRO+ZWwcM7fJvn1JfR2
PDLAaI3QUv7OLhSH32UfQsk+1ICq05m2HwSxiAviDRl5De66MEZDdvu03sUAQTHv
Wnw0Mr7Jgbjtn0DeUKLYwsRWg+spqoFTJHWGbb9RIb+3lxev7nIqOQIDAQABo4ID
5jCCA+IwHwYDVR0jBBgwFoAUPdNQpdagre7zSmAKZdMh1Pj41g8wHQYDVR0OBBYE
FGywQ1b+PegS7NkS9WPVxMoHr7B2MIGRBgNVHREEgYkwgYaCEHd3dy5kaWdpY2Vy
dC5jb22CDGRpZ2ljZXJ0LmNvbYIUY29udGVudC5kaWdpY2VydC5jb22CF3d3dy5v
cmlnaW4uZGlnaWNlcnQuY29tghJsb2dpbi5kaWdpY2VydC5jb22CEGFwaS5kaWdp
Y2VydC5jb22CD3dzLmRpZ2ljZXJ0LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l
BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1nMi5jcmwwNKAyoDCG
Lmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1nMi5jcmww
SwYDVR0gBEQwQjA3BglghkgBhv1sAgEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93
d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVngQwBATCBiAYIKwYBBQUHAQEEfDB6MCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUgYIKwYBBQUHMAKG
Rmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJFeHRlbmRl
ZFZhbGlkYXRpb25TZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAX4GCisGAQQB
1nkCBAIEggFuBIIBagFoAHYAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e
0YUAAAFkPjJMpQAABAMARzBFAiEAtvfxjDWBvpmqcq7+1X8lOyqKUJ8y5r31V4kV
4tzQSPcCIG8AAjqwQwLG6ObfgMe0B06AwM7K1JEAsyv8QP5r/EPUAHYAVhQGmi/X
wuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0AAAFkPjJMFgAABAMARzBFAiEAkDHY
U+MhibIUpVtiPAFyEzv35P3Vwn5ODseJmDI6dZkCICb4xzUGBy7aEQKJLOuM1F0A
vMjEEB1OQQc9IWEY7UdPAHYAh3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16g
gw8AAAFkPjJNlAAABAMARzBFAiBSMM3aExfTbMG1btIu+LCW9ALj4FT6scxUUgy5
+OSH/gIhAPtqsgHiH6m6Qml1E9smajxYa773+YZdxMKbtEEe2ZV8MA0GCSqGSIb3
DQEBCwUAA4IBAQCPcXLe1MjGJtwfihuI1S53GdokFAcl94ouoWxWd7ASfsufUyxs
FroxDhNwxd8mQOH7V3ehZTiot6P+xMZOrYxgJx5CXbcLt07RZHT0w/Pf052gq7bP
GbHsrjtlXq1MDn8c8D+Fnv2qSgE4f/9wQ1gMU4IKojaO4YH9FYoacA8puXUlK1pB
CuCK0jJykyAtD9z4oTD/ZLBQOmTJ4VwJ5rHNCfdI8akR9OYYyx9GCbeWYv5JCcIy
zPyvZe6ceICEnRGliU/EzryyWhq4Vx/zReBgoX6xOWfW1ZAota0etzo9pSWjOdrr
j1I7q0bAhL1eUuXE8FSm6M8ZogW/ZYkOHE2u
-----END CERTIFICATE-----
"""
    var certPEMData: Data { return certPEM.data(using: .utf8)! }
}


extension Data {
    func hexEncodedString(separation: String = "") -> String {
        return reduce("") {$0 + String(format: "%02X\(separation)", $1)}
    }
}

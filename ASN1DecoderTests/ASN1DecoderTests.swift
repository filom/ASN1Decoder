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
import CryptoKit



@testable import ASN1Decoder

class ASN1DecoderTests: XCTestCase {
    
    @available(OSX 10.12, *)
    func testDecodingPEM() throws {
        let x509 = try X509Certificate(data: certPEMData)
        
        XCTAssertEqual(x509.version,3)
        
        
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
        
        XCTAssertEqual(x509.serialNumber?.hexEncodedString(),
                       "0836BAA2556864172078584638D85C34")
        
        XCTAssertEqual(x509.notBefore?.description, "2018-06-26 00:00:00 +0000")
        XCTAssertEqual(x509.notAfter?.description, "2020-06-30 12:00:00 +0000")
        
        
        
        
        
       
        
        XCTAssertEqual(x509.subjectAlternativeNames,["www.digicert.com", "digicert.com", "content.digicert.com", "www.origin.digicert.com", "login.digicert.com", "api.digicert.com", "ws.digicert.com"]) // (2.5.29.17)
        XCTAssertEqual(x509.issuerAlternativeNames,[])
        
        XCTAssertEqual(x509.publicKey?.algName, "rsaEncryption")
        XCTAssertEqual(x509.publicKey!.key!.count*8,4096)
        XCTAssertEqual(x509.publicKey?.algParams, nil)
        XCTAssertEqual(x509.publicKey?.key?.hexEncodedString(), "CE9F85CA393030B7F69869B49C105D503B2563D0E568D4D9A5CA2CD63595B23E0D298B9DE0814A04F7C09E354933FBAB1C118A96358EA5DEA281E7AA49248A8D426A3D36858EF24D86FE34C88C5146A8D59822ADB78B8F87A9A5E2D7F1FF6961606B3935AA4CB200E41003FA79E9B1BD9B93A4FC804CFC16672EA5492C624EC7D8A1806D5D23D0EBEAF6A9FBC41A3D16AEDEDF6C11DD9CC5EE08C7B80B75A606DEFC6C61FDC1C9C29348AB72ADB917D50CB476C4B1CBE182336113C44D6031AEEF468990FD9A19A3C21BE79905A7A9484FA50E3A491DCA225DA563D7219665B19479C247A0583B093FB5EFEE713458C918D7ED3988D62DAF3651861967070D80A0C18D23EB6C0572D029E65F585994DF46E19335FDF699AF2182777F57D018B6A8E389D01237649C8BE99B41CC82F6A06029D05679E1252B73C98CF7DB87E558B3D2A79ECE41E34CB6BE8EE56D07756CA151953E0F847AC0E6D840C6796E2623461B40423320F0455011F67311DAF45863B92511CB1F2A2DF2D12B5CCF43885E5C09BCDF7237AEA229364875BEBDBB8F6A03221D333DFB796BD2844EF995B070CEDF26F9F525F4763C32C0688DD052FECE2E1487DF651F42C93ED480AAD399B61F04B1880BE20D19790DEEBA30464376FBB4DEC5004131EF5A7C3432BEC981B8ED9F40DE50A2D8C2C45683EB29AA81532475866DBF5121BFB79717AFEE722A39")
        
        if #available(OSX 10.15,iOS 13.0, *) {
            
            XCTAssertEqual(SHA256.hash(data: x509.encodedTBSCertificate!).hexEncodedString(separation: ":"),"83:BF:80:95:73:69:D2:77:CB:58:93:64:BC:40:C5:AD:91:B9:73:4E:AD:B7:BC:F6:96:2A:48:EF:7F:F9:02:1E")
            XCTAssertEqual(SHA256.hash(data: x509.encodedCertificate!).hexEncodedString(separation: ":"),"C7:32:93:B5:94:A3:52:18:4A:D8:7E:5A:95:FB:39:B7:3B:0F:F6:80:02:A4:AB:EA:5E:74:F3:50:24:55:DB:D3" )
            
        } else {
            // Fallback on earlier versions
            
        }
                
        
        XCTAssertEqual(x509.sigAlgName, "sha256WithRSAEncryption")
        XCTAssertEqual(x509.sigAlgParams?.hexEncodedString(), nil)
        XCTAssertEqual(x509.signature?.hexEncodedString(separation: ":"),                              "8F:71:72:DE:D4:C8:C6:26:DC:1F:8A:1B:88:D5:2E:77:19:DA:24:14:07:25:F7:8A:2E:A1:6C:56:77:B0:12:7E:CB:9F:53:2C:6C:16:BA:31:0E:13:70:C5:DF:26:40:E1:FB:57:77:A1:65:38:A8:B7:A3:FE:C4:C6:4E:AD:8C:60:27:1E:42:5D:B7:0B:B7:4E:D1:64:74:F4:C3:F3:DF:D3:9D:A0:AB:B6:CF:19:B1:EC:AE:3B:65:5E:AD:4C:0E:7F:1C:F0:3F:85:9E:FD:AA:4A:01:38:7F:FF:70:43:58:0C:53:82:0A:A2:36:8E:E1:81:FD:15:8A:1A:70:0F:29:B9:75:25:2B:5A:41:0A:E0:8A:D2:32:72:93:20:2D:0F:DC:F8:A1:30:FF:64:B0:50:3A:64:C9:E1:5C:09:E6:B1:CD:09:F7:48:F1:A9:11:F4:E6:18:CB:1F:46:09:B7:96:62:FE:49:09:C2:32:CC:FC:AF:65:EE:9C:78:80:84:9D:11:A5:89:4F:C4:CE:BC:B2:5A:1A:B8:57:1F:F3:45:E0:60:A1:7E:B1:39:67:D6:D5:90:28:B5:AD:1E:B7:3A:3D:A5:25:A3:39:DA:EB:8F:52:3B:AB:46:C0:84:BD:5E:52:E5:C4:F0:54:A6:E8:CF:19:A2:05:BF:65:89:0E:1C:4D:AE")
        XCTAssertEqual(x509.signature?.count,256)
        
        
    }
    
    

    @available(OSX 10.12,iOS 10.0, *)
    func testSignature()  throws  {
        
        let publicKeyCA = try X509PublicKey(data: publicKeyCaPEMData)
        let x509 = try X509Certificate(data: certPEMData)
        
        let encodedKey = publicKeyCA.encodedKey()
        
        
        // creating a SecureKey
        var attributes: CFDictionary {
            return [kSecAttrKeyType         : kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass        : kSecAttrKeyClassPublic,
                    kSecAttrKeySizeInBits   : 2048] as CFDictionary
        }
        
        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateWithData(encodedKey! as CFData, attributes, &error) else {
            print(error.debugDescription)
            throw  error as! Error
        }
        
        XCTAssertTrue(SecKeyVerifySignature(secKey, .rsaSignatureMessagePKCS1v15SHA256, x509.encodedTBSCertificate! as CFData, x509.signature! as CFData, &error))

    }
    
    func testExtensions()  throws {
        
        let x509 = try X509Certificate(data: certPEMData)
      
  
        XCTAssertEqual(x509.basicConstraints.isCA, false )
        XCTAssertEqual(x509.basicConstraints.pathLengthConstraint, nil )
        
        XCTAssertEqual(x509.crlDistributionPoints[0].fullName?.URI,"http://crl3.digicert.com/sha2-ev-server-g2.crl")
        XCTAssertEqual(x509.crlDistributionPoints[1].fullName?.URI,"http://crl4.digicert.com/sha2-ev-server-g2.crl")
        
        XCTAssertEqual(x509.certificatePolicies[0].identifier,"2.16.840.1.114412.2.1")
        XCTAssertEqual(x509.certificatePolicies[0].qualifierInfo?.identifier,"1.3.6.1.5.5.7.2.1")
        XCTAssertEqual(x509.certificatePolicies[0].qualifierInfo?.qualifier,"https://www.digicert.com/CPS")
        
        XCTAssertEqual(x509.certificatePolicies[1].identifier,"2.23.140.1.1")

        XCTAssertEqual(x509.authorityKeyIdentifier.identifier?.hexEncodedString(separation: ":"),"3D:D3:50:A5:D6:A0:AD:EE:F3:4A:60:0A:65:D3:21:D4:F8:F8:D6:0F")
        XCTAssertEqual(x509.subjectKeyIdentifier!.hexEncodedString(separation: ":"),"6C:B0:43:56:FE:3D:E8:12:EC:D9:12:F5:63:D5:C4:CA:07:AF:B0:76")
        
        XCTAssertEqual(x509.nonCriticalExtensionOIDs,["2.5.29.35", "2.5.29.14", "2.5.29.17", "2.5.29.37", "2.5.29.31", "2.5.29.32", "1.3.6.1.5.5.7.1.1", "1.3.6.1.4.1.11129.2.4.2"])
        XCTAssertEqual(x509.criticalExtensionOIDs,["2.5.29.15", "2.5.29.19"])
        
        XCTAssertEqual(x509.keyUsage, [true, false, true, false, false, false, false, false]) // (2.5.29.15)
        
        XCTAssertEqual(x509.extendedKeyUsage,["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"])  // (2.5.29.37)
        
        
        XCTAssertEqual(x509.extensionObject(oid: "1.3.6.1.5.5.7.1.1")?.valueAsStrings,[])  // AuthorityInfoAccess    (1.3.6.1.5.5.7.1.1)                            // FIXME
        XCTAssertEqual(x509.extensionObject(oid: "1.3.6.1.4.1.11129.2.4.2")?.valueAsStrings,[])  // Extended validation certificates    (1.3.6.1.4.1.11129.2.4.2)   // FIXME
        
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
    
    
    let publicKeyCaPEM = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA11OkBFH4maYWSEtnJ6qT
SdA57QywsACH8WcohoWMjmPavLFAOOLT9eylBRi4PT7FmRcy7BiM+vEMpmQhhcsH
EDSwUogrH2ib0rGPErCz0ueIHx/vOHdUU1+AeT8uGqqoHksrDau3Y7k1t30UvFlL
31FK0qHiDOKQgodqrurXZNaYVej9rxpQbFS8EfL9SvKdu38O9NW+jhaJElXYwHE0
7vbcLezEhyWGjdgh5LBNDIncOSYX3fbXlIXYBCFwnW9v/1y6GeFFy1ZXKH4cDUFX
qre4J7ux5Poq7yEjdRqtLZuGNYycd7VzrdiULeTzDJ3uwU5ifhfAcZ4s3vH5ECgZ
MwIDAQAB
-----END PUBLIC KEY-----
"""
    
    var publicKeyCaPEMData: Data { return publicKeyCaPEM.data(using: .utf8)! }
    
    
    let CaPEM = """
-----BEGIN CERTIFICATE-----
MIIEtjCCA56gAwIBAgIQDHmpRLCMEZUgkmFf4msdgzANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j
ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowdTEL
MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
LmRpZ2ljZXJ0LmNvbTE0MDIGA1UEAxMrRGlnaUNlcnQgU0hBMiBFeHRlbmRlZCBW
YWxpZGF0aW9uIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANdTpARR+JmmFkhLZyeqk0nQOe0MsLAAh/FnKIaFjI5j2ryxQDji0/XspQUY
uD0+xZkXMuwYjPrxDKZkIYXLBxA0sFKIKx9om9KxjxKws9LniB8f7zh3VFNfgHk/
LhqqqB5LKw2rt2O5Nbd9FLxZS99RStKh4gzikIKHaq7q12TWmFXo/a8aUGxUvBHy
/Urynbt/DvTVvo4WiRJV2MBxNO723C3sxIclho3YIeSwTQyJ3DkmF93215SF2AQh
cJ1vb/9cuhnhRctWVyh+HA1BV6q3uCe7seT6Ku8hI3UarS2bhjWMnHe1c63YlC3k
8wyd7sFOYn4XwHGeLN7x+RAoGTMCAwEAAaOCAUkwggFFMBIGA1UdEwEB/wQIMAYB
Af8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEF
BQcDAjA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsNC5kaWdpY2Vy
dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMD0GA1UdIAQ2
MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
b20vQ1BTMB0GA1UdDgQWBBQ901Cl1qCt7vNKYApl0yHU+PjWDzAfBgNVHSMEGDAW
gBSxPsNpA/i/RwHUmCYaCALvY2QrwzANBgkqhkiG9w0BAQsFAAOCAQEAnbbQkIbh
hgLtxaDwNBx0wY12zIYKqPBKikLWP8ipTa18CK3mtlC4ohpNiAexKSHc59rGPCHg
4xFJcKx6HQGkyhE6V6t9VypAdP3THYUYUN9XR3WhfVUgLkc3UHKMf4Ib0mKPLQNa
2sPIoc4sUqIAY+tzunHISScjl2SFnjgOrWNoPLpSgVh5oywM395t6zHyuqB8bPEs
1OG9d4Q3A84ytciagRpKkk47RpqF/oOi+Z6Mo8wNXrM9zwR4jxQUezKcxwCmXMS1
oVWNWlZopCJwqjyBcdmdqEU79OX2olHdx3ti6G8MdOu42vi/hw15UJGQmxg7kVkn
8TUoE6smftX3eg==
-----END CERTIFICATE-----
"""
    
    var CaPEMData: Data { return CaPEM.data(using: .utf8)! }
    
    
    
}


extension Data {
    func hexEncodedString(separation: String = "") -> String {
        var hexString = reduce("") {$0 + String(format: "%02X\(separation)", $1)}
        if separation != "" {hexString.removeLast()}
        return hexString
    }
}


@available(OSX 10.15,iOS 13.0, *)
extension SHA256Digest {
    func hexEncodedString(separation: String = "") -> String {
        var hexString = reduce("") {$0 + String(format: "%02X\(separation)", $1)}
        if separation != "" {hexString.removeLast()}
        return hexString
    }
}

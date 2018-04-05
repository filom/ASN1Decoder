# ASN1Decoder
ASN1 DER Decoder for X.509 Certificate

## Requirements

- iOS 9.0+ | macOS 10.10+
- Xcode 9

## Integration

#### CocoaPods (iOS 9+, OS X 10.10+)

You can use [CocoaPods](http://cocoapods.org/) to install `ASN1Decoder` by adding it to your `Podfile`:

```ruby
platform :ios, '9.0'
use_frameworks!

target 'MyApp' do
	pod 'ASN1Decoder'
end
```

#### Carthage (iOS 9+, OS X 10.10+)

You can use [Carthage](https://github.com/Carthage/Carthage) to install `ASN1Decoder` by adding it to your `Cartfile`:

```
github "filom/ASN1Decoder"
```


## Usage

### Parse a DER/PEM X.509 certificate

``` swift
import ASN1Decoder

do {
    let x509 = try X509Certificate(data: certData)

    let subject = x509.subjectDistinguishedName ?? ""

} catch {
    print(error)
}
```



### Usage for SSL pinning

Define a delegate for URLSession

``` swift
import Security
import ASN1Decoder

class PinningURLSessionDelegate: NSObject, URLSessionDelegate {

    var publicKeyHexEncoded: String!

    public init(publicKeyHexEncoded: String) {
        self.publicKeyHexEncoded = publicKeyHexEncoded.uppercased()
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {

        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)

                if status == errSecSuccess {

                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {

                        let serverCertificateCFData = SecCertificateCopyData(serverCertificate)
                        let data = CFDataGetBytePtr(serverCertificateCFData)
                        let size = CFDataGetLength(serverCertificateCFData)
                        let certData = NSData(bytes: data, length: size)

                        do {
                            let x509cert = try X509Certificate(data: certData as Data)

                            if let pk = x509cert.publicKey?.key {

                                let serverPkHexEncoded = dataToHexString(pk)

                                if publicKeyHexEncoded == serverPkHexEncoded {
                                    completionHandler(.useCredential, URLCredential(trust:serverTrust))
                                    return
                                }
                            }

                        } catch {
                            print(error)
                        }
                    }
                }
            }
        }

        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    func dataToHexString(_ data: Data) -> String {
        return data.map { String(format: "%02X", $0) }.joined()
    }
}
```


Then create a URLSession and use it as usual

``` swift
let publicKeyHexEncoded = "..." // your HTTPS certifcate public key

let session = URLSession(
                configuration: URLSessionConfiguration.ephemeral,
                delegate: PinningURLSessionDelegate(publicKeyHexEncoded: publicKeyHexEncoded),
                delegateQueue: nil)
```


To extract the public key from your certificate with openssl use this command line

```
openssl x509 -modulus -noout < certificate.cer
```


### How to use for AppStore receipt parse

``` swift
import ASN1Decoder

if let appStoreReceiptURL = Bundle.main.appStoreReceiptURL,
            FileManager.default.fileExists(atPath: appStoreReceiptURL.path) {

    do {
        let receiptData = try Data(contentsOf: appStoreReceiptURL, options: .alwaysMapped)

        let pkcs7 = try PKCS7(data: receiptData)

        if let receiptInfo = pkcs7.receipt() {
            print(receiptInfo.originalApplicationVersion)
        }

    } catch {
        print(error)
    }
}
```

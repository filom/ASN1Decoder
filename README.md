# ASN1Decoder
ASN1 DER Decoder for X.509 Certificate

## Requirements

- iOS 8.0+ | macOS 10.10+ 
- Xcode 8

## Integration

#### CocoaPods (iOS 9+, OS X 10.10+)

You can use [CocoaPods](http://cocoapods.org/) to install `ASN1Decoder`by adding it to your `Podfile`:

```ruby
platform :ios, '9.0'
use_frameworks!

target 'MyApp' do
	pod 'ASN1Decoder'
end
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

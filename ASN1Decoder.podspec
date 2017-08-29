Pod::Spec.new do |s|
  s.name         = "ASN1Decoder"
  s.version      = "1.0.0"
  s.summary      = "ASN1 DER Decoder for X.509 certificate"
  s.description  = "ASN1 DER Decoder to parse X.509 certificate"
  s.homepage     = "https://github.com/filom/ASN1Decoder"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author       = { "Filippo Maguolo" => "maguolo.ios@outlook.com" }
  s.ios.deployment_target = "9.0"
  s.osx.deployment_target = "10.10"
  s.source        = { :git => "https://github.com/filom/ASN1Decoder.git", :tag => s.version }
  s.source_files  = "ASN1Decoder/*.swift"
  s.frameworks    = "Foundation"
  s.pod_target_xcconfig =  {
        'SWIFT_VERSION' => '3.0',
  }
end

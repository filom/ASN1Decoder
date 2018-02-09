//
//  PKCS7_AppleReceipt.swift
//
//  Copyright © 2018 Filippo Maguolo.
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

import Foundation

extension PKCS7 {
    
    public class ReceiptInfo {
        var bundleIdentifier: String?
        var bundleVersion: String?
        var originalApplicationVersion: String?
        var receiptCreationDate: Date?
        var receiptCreationDateString: String?
        var receiptExpirationDate: Date?
        var receiptExpirationDateString: String?
    }
    
    public func receipt() -> ReceiptInfo? {
        
        if let block = mainBlock.findOid(OID_Data) {
            
            if let receiptBlock = block.parent?.sub?.last?.sub(0)?.sub(0) {
                
                let receiptInfo = ReceiptInfo()
                
                let parseDate: (String) -> Date? = { dateString in
                    let rfc3339DateFormatter = DateFormatter()
                    rfc3339DateFormatter.locale = Locale(identifier: "en_US_POSIX")
                    rfc3339DateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
                    rfc3339DateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
                    return rfc3339DateFormatter.date(from: dateString)
                }
                
                for item in receiptBlock.sub ?? [] {
                    
                    let fieldType = (item.sub(0)?.value as? Data)?.toIntValue() ?? 0
                    
                    guard let fieldValue = item.sub(2)?.sub?.first?.value as? String else {
                        continue
                    }
                    
                    switch fieldType {
                    case 2:
                        receiptInfo.bundleIdentifier = fieldValue
                        
                    case 3:
                        receiptInfo.bundleVersion = fieldValue
                        
                    case 19:
                        receiptInfo.originalApplicationVersion = fieldValue
                        
                    case 12:
                        receiptInfo.receiptCreationDateString = fieldValue
                        receiptInfo.receiptCreationDate = parseDate(fieldValue)
                        
                    case 21:
                        receiptInfo.receiptExpirationDateString = fieldValue
                        receiptInfo.receiptExpirationDate = parseDate(fieldValue)
                        
                    default: break
                    }
                }
                return receiptInfo
            }
        }
        return nil
    }
    
}

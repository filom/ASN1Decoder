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

/*
 This extension allow to parse the content of an Apple receipt from the AppStore.
 
 Reference documentation
 https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html
 */
extension PKCS7 {
    
    public struct ReceiptInfo {
        
        /// CFBundleIdentifier in Info.plist
        public fileprivate(set) var bundleIdentifier: String?
        
        /// CFBundleVersion (in iOS) or CFBundleShortVersionString (in macOS) in Info.plist
        public fileprivate(set) var bundleVersion: String?
        
        /// CFBundleVersion (in iOS) or CFBundleShortVersionString (in macOS) in Info.plist
        public fileprivate(set) var originalApplicationVersion: String?
        
        public fileprivate(set) var receiptCreationDate: Date?
        public fileprivate(set) var receiptCreationDateString: String?
        public fileprivate(set) var receiptExpirationDate: Date?
        public fileprivate(set) var receiptExpirationDateString: String?
        public fileprivate(set) var inAppPurchases: [InAppPurchaseInfo]?
    }
    
    public struct InAppPurchaseInfo {
        public fileprivate(set) var quantity: UInt64?
        public fileprivate(set) var productId: String?
        public fileprivate(set) var transactionId: String?
        public fileprivate(set) var originalTransactionId: String?
        public fileprivate(set) var purchaseDate: Date?
        public fileprivate(set) var originalPurchaseDate: Date?
        public fileprivate(set) var expiresDate: Date?
        public fileprivate(set) var isInIntroOfferPeriod: UInt64?
        public fileprivate(set) var cancellationDate: Date?
        public fileprivate(set) var webOrderLineItemId: UInt64?
    }
    
    
    public func receipt() -> ReceiptInfo? {
        guard let block = mainBlock.findOid(OID_Data) else { return nil }
        guard let receiptBlock = block.parent?.sub?.last?.sub(0)?.sub(0) else { return nil }
        var receiptInfo = ReceiptInfo()
        
        let parseDate: (String) -> Date? = { dateString in
            let rfc3339DateFormatter = DateFormatter()
            rfc3339DateFormatter.locale = Locale(identifier: "en_US_POSIX")
            rfc3339DateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
            rfc3339DateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
            return rfc3339DateFormatter.date(from: dateString)
        }
        
        for item in receiptBlock.sub ?? [] {
            let fieldType = (item.sub(0)?.value as? Data)?.toIntValue() ?? 0
            let fieldValueString = item.sub(2)?.sub?.first?.value as? String
            switch fieldType {
            case 2:
                receiptInfo.bundleIdentifier = fieldValueString
                
            case 3:
                receiptInfo.bundleVersion = fieldValueString
                
            case 19:
                receiptInfo.originalApplicationVersion = fieldValueString
                
            case 12:
                guard let fieldValueString = fieldValueString else { continue }
                receiptInfo.receiptCreationDateString = fieldValueString
                receiptInfo.receiptCreationDate = parseDate(fieldValueString)
                
            case 21:
                guard let fieldValueString = fieldValueString else { continue }
                receiptInfo.receiptExpirationDateString = fieldValueString
                receiptInfo.receiptExpirationDate = parseDate(fieldValueString)
                
            case 17:
                var inAppPurchaseInfo = InAppPurchaseInfo()
                for subItem in item.sub(2)?.sub?.first?.sub ?? [] {
                    let fieldType = (subItem.sub(0)?.value as? Data)?.toIntValue() ?? 0
                    let fieldValue = subItem.sub(2)?.sub?.first?.value
                    switch fieldType {
                    case 1701:
                        inAppPurchaseInfo.quantity = (fieldValue as? Data)?.toIntValue()
                    case 1702:
                        inAppPurchaseInfo.productId = fieldValue as? String
                    case 1703:
                        inAppPurchaseInfo.transactionId = fieldValue as? String
                    case 1705:
                        inAppPurchaseInfo.originalTransactionId = fieldValue as? String
                    case 1704:
                        guard let fieldValueString = fieldValue as? String else { continue }
                        inAppPurchaseInfo.purchaseDate = parseDate(fieldValueString)
                    case 1706:
                        guard let fieldValueString = fieldValue as? String else { continue }
                        inAppPurchaseInfo.originalPurchaseDate = parseDate(fieldValueString)
                    case 1708:
                        guard let fieldValueString = fieldValue as? String else { continue }
                        inAppPurchaseInfo.expiresDate = parseDate(fieldValueString)
                    case 1719:
                        inAppPurchaseInfo.isInIntroOfferPeriod = (fieldValue as? Data)?.toIntValue()
                    case 1712:
                        guard let fieldValueString = fieldValue as? String else { continue }
                        inAppPurchaseInfo.cancellationDate = parseDate(fieldValueString)
                    case 1711:
                        inAppPurchaseInfo.webOrderLineItemId = (fieldValue as? Data)?.toIntValue()
                    default:
                        break
                    }
                }
                if receiptInfo.inAppPurchases == nil {
                    receiptInfo.inAppPurchases = []
                }
                receiptInfo.inAppPurchases?.append(inAppPurchaseInfo)
                
            default:
                break
            }
        }
        return receiptInfo
    }
    
}

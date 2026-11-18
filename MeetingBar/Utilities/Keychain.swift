//
//  Keychain.swift
//  MeetingBar
//
//  Created by Andrii Leitsius on 19.05.2025.
//  Copyright © 2025 Andrii Leitsius. All rights reserved.
//

import Security
import Foundation

enum KeychainQueryFactory {
    static func saveQuery(data: Data, service: String) -> [String: Any] {
        [
            kSecClass              as String: kSecClassGenericPassword,
            kSecAttrService        as String: service,
            kSecValueData          as String: data,
            kSecAttrAccessible     as String: kSecAttrAccessibleAfterFirstUnlock
        ]
    }

    static func loadQuery(service: String) -> [String: Any] {
        [
            kSecClass               as String: kSecClassGenericPassword,
            kSecAttrService         as String: service,
            kSecReturnData          as String: true,
            kSecMatchLimit          as String: kSecMatchLimitOne
        ]
    }

    static func deleteQuery(service: String) -> [String: Any] {
        [
            kSecClass        as String: kSecClassGenericPassword,
            kSecAttrService  as String: service
        ]
    }
}

enum Keychain {
    // MARK: - Public helpers
    @discardableResult
    static func save(data: Data, for service: String) -> Bool {
        delete(for: service)                                     // overwrite if exists

        let query = KeychainQueryFactory.saveQuery(data: data, service: service)
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            MeetingBarLogger.calendar.error("Keychain save failed, OSStatus \(status)")
        }
        return status == errSecSuccess
    }

    static func load(for service: String) -> Data? {
        let query = KeychainQueryFactory.loadQuery(service: service)
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            if status != errSecItemNotFound {
                MeetingBarLogger.calendar.error("Keychain load failed, OSStatus \(status)")
            }
            return nil
        }
        return item as? Data
    }

    @discardableResult
    static func delete(for service: String) -> Bool {
        let query = KeychainQueryFactory.deleteQuery(service: service)
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess, status != errSecItemNotFound {
            MeetingBarLogger.calendar.error("Keychain delete failed, OSStatus \(status)")
        }
        return status == errSecSuccess
    }
}

// Keymaster, access Keychain secrets guarded by TouchID
//
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func setPassword(key: String, password: String) -> Bool {
  guard let passwordData = password.data(using: .utf8) else {
    print("Error: Failed to convert password string to UTF-8 bytes")
    return false
  }

  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: passwordData
  ]

  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func deletePassword(key: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: .utf8)
  else { return nil }

  return password
}

func usage() {
  print("keymaster [get|set|delete] [key] [secret]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 2 || inputArgs.count > 3) {
    usage()
    exit(EXIT_FAILURE)
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  if (action == "set" && inputArgs.count == 3) {
    secret = inputArgs[2]
  }

  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0

  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  if (action == "set") {
    context.evaluatePolicy(policy, localizedReason: "set the password for \(key)") { success, error in
      if success && error == nil {
      guard setPassword(key: key, password: secret) else {
        print("Error setting password")
        exit(EXIT_FAILURE)
      }
        print("Key \(key) has been successfully set in the keychain")
      exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "get") {
    context.evaluatePolicy(policy, localizedReason: "access the password for \(key)") { success, error in
      if success && error == nil {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "delete") {
    context.evaluatePolicy(policy, localizedReason: "delete the password for \(key)") { success, error in
      if success && error == nil {
        guard deletePassword(key: key) else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()

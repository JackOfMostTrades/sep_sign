import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct Output: Encodable {
  var isAvailable: Bool?
  var privateKey: String?
  var publicKey: String?
  var signature: String?
}

let argsv = Array(CommandLine.arguments.dropFirst())
var generate = false
var requireBiometry = false
var requireUnlocked = false
var privateKeyArg: String?
var dataArg: String?

var i = 0
while i < argsv.count {
  switch argsv[i] {
    case "--generate":
      generate = true
    case "--requireBiometry":
      requireBiometry = true
    case "--requireUnlocked":
      requireUnlocked = true
    case "--key":
      privateKeyArg = argsv[i+1]
      i += 1
    case "--data":
      dataArg = argsv[i+1]
      i += 1
    default:
      print("Invalid argument: " + argsv[i])
      exit(1)
  }
  i += 1
}

let authContext = LAContext()
var output: Output = Output()
output.isAvailable = CryptoKit.SecureEnclave.isAvailable

var privateKey: CryptoKit.SecureEnclave.P256.Signing.PrivateKey?
if generate {
  if privateKeyArg != nil {
    print("Cannot specify both --generate and --key")
    exit(1)
  }

  let protection: CFTypeRef
  if (requireUnlocked) {
    protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  } else {
    protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
  }

  let flags: SecAccessControlCreateFlags
  if (requireBiometry) {
    flags = [SecAccessControlCreateFlags.privateKeyUsage, SecAccessControlCreateFlags.biometryCurrentSet]
  } else {
    flags = [SecAccessControlCreateFlags.privateKeyUsage]
  }

  let accessCtrl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    protection,
    flags,
    nil
  )
  precondition(accessCtrl != nil, "SecAccessControlCreateWithFlags failed")

  let key = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(
    accessControl: accessCtrl!,
    authenticationContext: authContext
  )
  privateKey = key
  output.privateKey = key.dataRepresentation.base64EncodedString()
  output.publicKey = key.publicKey.derRepresentation.base64EncodedString()
} else if privateKeyArg != nil {
  privateKey = try CryptoKit.SecureEnclave.P256.Signing.PrivateKey(
    dataRepresentation: Data(base64Encoded: privateKeyArg!)!,
    authenticationContext: authContext
  )
}

if let dataB64 = dataArg {
  if privateKey == nil {
    print("Cannot specify --data without specifying --generate or --key")
    exit(1)
  }
  let data = Data(base64Encoded: dataB64)!
  let sig = try privateKey!.signature(for: data)
  output.signature = sig.derRepresentation.base64EncodedString()
}

let outputJson = try JSONEncoder().encode(output)
print(String(data: outputJson, encoding: .utf8)!)


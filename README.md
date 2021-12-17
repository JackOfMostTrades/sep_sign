# sep_sign

This Go library provides a limited way to use the keys backed by Apple's Secure Enclave Processor (SEP).
This library uses the [CryptoKit](https://developer.apple.com/documentation/cryptokit/secureenclave) library to access the Secure Enclave.
Since this library is only available with a Swift API, I have written a small helper CLI in swift.
The CLI is [embedded](https://pkg.go.dev/embed) in this package and will be extracted (into a temporary file that is immediately cleanup up after execution) and run as needed.

It would be possible to implement this library instead using cgo (e.g. [using an objective-c bridge](https://github.com/smasher164/swift-cgo-example)), but that requires linking agaist all of the swift runtime libraries which is a bit heavy-handed. Relying on an embedded binary seemed like the less obtrusive option.

# Rebuilding the binary

If you're just importing this library you shouldn't need to rebuild the native binary.
If you're doing development and want to rebuild the binary, you should be able to just run `go generate`, assuming you're on a macOS device with xcode installed.

# Usage

```
package main

import "github.com/jackofmosttrades/sep_sign"

func main() {
    // Check if SEP is available on this device and login session
    available, err := sep_sign.IsAvailable()
    if err != nil { panic(err) }
    if !available {
        println("SEP is not available!")
    }

    // Generate a new key. The "privateKey" returned is an opaque []byte
    // that represents a handle in the SEP.
    privateKey, publicKey, err := sep_sign.Generate()
    if err != nil { panic(err) }

    // Generate some random data to sign
    data := make([]byte, 1024)
    _, err = rand.Read(data)
    if err != nil { panic(err) }

    // Sign the data using the opaque key handle from above
    sig, err := sep_sign.SignData(privateKey, data)
    if err != nil { panic(err) }

    hash := sha256.Sum256(data)
    verified := ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), hash[:], sig)
    if !verified {
        println("Failed to verify signature!")
    }
}
```
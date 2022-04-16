# NUMS
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/nums/blob/master/LICENSE.md) 
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/nums/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/nums/releases)
[![GoDoc](https://godoc.org/github.com/pedroalbanese/nums?status.png)](http://godoc.org/github.com/pedroalbanese/nums)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/nums)](https://goreportcard.com/report/github.com/pedroalbanese/nums)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/nums)](https://github.com/pedroalbanese/nums/releases)
### Microsoft Nothing Up My Sleeve Elliptic curves

## Usage
```
Usage of nums:
  -dec
        Decrypt with Private key
  -derive
        Derive shared secret key
  -enc
        Encrypt with Public key
  -key string
        Private/Public key
  -keygen
        Generate keypair
  -pub string
        Remote's side Public key
  -sign
        Sign with Private key
  -signature string
        Signature
  -verify
        Verify with Public key
```
## Examples
#### Asymmetric keypair generation:
```sh
./nums -keygen 
```
#### Digital signature (ECDSA):
```sh
./nums -sign -key $prvkey < file.ext > sign.txt
sign=$(cat sign.txt)
./nums -verify -key $pubkey -signature $sign < file.ext
```
#### Asymmetric encryption:
```sh
./nums -enc -key $pubkey < file.ext > file.enc
./nums -dec -key $prvkey < file.enc
```
#### Shared key agreement (ECDH):
```sh
./nums -derive -key $prvkey -pub $pubkey
```

## License

This project is licensed under the ISC License.

##### Industrial-Grade Reliability. Copyright (c) 2020-2022 ALBANESE Research Lab.

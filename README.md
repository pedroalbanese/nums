# NUMS
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/nums/blob/master/LICENSE.md) 
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/nums/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/nums/releases)
[![GoDoc](https://godoc.org/github.com/pedroalbanese/nums?status.png)](http://godoc.org/github.com/pedroalbanese/nums)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/nums)](https://goreportcard.com/report/github.com/pedroalbanese/nums)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/nums)](https://github.com/pedroalbanese/nums/releases)
### Microsoft Nothing Up My Sleeve Elliptic curves
[NUMS](http://www.watersprings.org/pub/id/draft-black-numscurves-01.html) (Nothing Up My Sleeve) curves, which are supported in the MSRElliptic Curve Cryptography Library (a.k.a. MSR ECCLib).

These curves are elliptic curves over a prime field, just like the NIST or Brainpool curves. However, the domain-parameters are choosen using a VERY TIGHT DESIGN SPACE to ensure, that the introduction of a backdoor is infeasable. For a desired size of s bits the prime p is choosen as p = 2^s - c with the smallest c where c>0 and p mod 4 = 3 and p being prime.

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

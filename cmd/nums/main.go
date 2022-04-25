// Nothing Up My Sleeve Elliptic curve NUMSP512d1 Digital Signer/Diffie-Hellman/Crypter
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/pedroalbanese/eccrypt/eccrypt512"
	"github.com/pedroalbanese/nums"
	"github.com/pedroalbanese/randomart"
)

var (
	dec    = flag.Bool("dec", false, "Decrypt with Private key.")
	derive = flag.Bool("derive", false, "Derive shared secret key.")
	enc    = flag.Bool("enc", false, "Encrypt with Public key.")
	key    = flag.String("key", "", "Private/Public key.")
	keygen = flag.Bool("keygen", false, "Generate keypair.")
	public = flag.String("pub", "", "Remote's side Public key.")
	sig    = flag.String("signature", "", "Signature.")
	sign   = flag.Bool("sign", false, "Sign with Private key.")
	verify = flag.Bool("verify", false, "Verify with Public key.")
)

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "NUMS Signer/DH/Crypter - ALBANESE Research Lab")
		fmt.Fprintln(os.Stderr, "Microsoft Nothing Up My Sleeve Elliptic curves\n")
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nCopyright (c) 2022 Pedro F. Albanese - ALBANESE Lab")
		os.Exit(2)
	}

	var privatekey *ecdsa.PrivateKey
	var pubkey ecdsa.PublicKey
	var pub *ecdsa.PublicKey
	var err error
	var pubkeyCurve elliptic.Curve

	pubkeyCurve = nums.P512()

	if *keygen {
		if *key != "" {
			privatekey, err = ReadPrivateKeyFromHex(*key)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			privatekey = new(ecdsa.PrivateKey)
			privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			for len(WritePrivateKeyToHex(privatekey)) != 128 {
				privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				break
			}
			if len(WritePrivateKeyToHex(privatekey)) != 128 {
				log.Fatal("Private key too short!")
				os.Exit(1)
			}
		}
		pubkey = privatekey.PublicKey
		fmt.Println("Private= " + WritePrivateKeyToHex(privatekey))
		fmt.Println("Public= " + WritePublicKeyToHex(&pubkey))
		os.Exit(0)
	}

	if *derive {
		private, err := ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		public, err := ReadPublicKeyFromHex(*public)
		if err != nil {
			log.Fatal(err)
		}
		b, _ := public.Curve.ScalarMult(public.X, public.Y, private.D.Bytes())

		Sum512 := func(msg []byte) []byte {
			res := sha512.New()
			res.Write(msg)
			hash := res.Sum(nil)
			return []byte(hash)
		}
		shared := Sum512(b.Bytes())
		fmt.Printf("Shared= %x\n", shared[:32])
		os.Exit(0)
	}

	if *sign {
		var h hash.Hash
		h = sha512.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}
		privatekey, err = ReadPrivateKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := Sign(h.Sum(nil), privatekey)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", signature)
		os.Exit(0)
	}

	if *verify {
		var h hash.Hash
		h = sha512.New()

		if _, err := io.Copy(h, os.Stdin); err != nil {
			panic(err)
		}
		pub, err = ReadPublicKeyFromHex(*key)
		if err != nil {
			log.Fatal(err)
		}
		sig, _ := hex.DecodeString(*sig)

		verifystatus := Verify(h.Sum(nil), sig, pub)
		fmt.Println(verifystatus)
		if verifystatus {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *enc {
		public, err := ReadPublicKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		ciphertxt, err := eccrypt512.EncryptAsn1(public, []byte(scanner), rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%x\n", ciphertxt)
		os.Exit(0)
	}

	if *dec {
		private, err := ReadPrivateKeyFromHexX(*key)
		if err != nil {
			log.Fatal(err)
		}
		buf := bytes.NewBuffer(nil)
		data := os.Stdin
		io.Copy(buf, data)
		scanner := string(buf.Bytes())
		str, _ := hex.DecodeString(string(scanner))
		plaintxt, err := eccrypt512.DecryptAsn1(private, []byte(str))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", plaintxt)
		os.Exit(0)
	}

	if *key == "-" {
		fmt.Println(randomart.FromFile(os.Stdin))
	} else {
		fmt.Println(randomart.FromString(*key))
	}
}

func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {

	Sum512 := func(msg []byte) []byte {
		res := sha512.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	digest := Sum512(data)

	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}

	params := privkey.Curve.Params()
	curveOrderByteSize := params.P.BitLen() / 8
	rBytes, sBytes := r.Bytes(), s.Bytes()
	signature := make([]byte, curveOrderByteSize*2)
	copy(signature[curveOrderByteSize-len(rBytes):], rBytes)
	copy(signature[curveOrderByteSize*2-len(sBytes):], sBytes)

	return signature, nil
}

func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {

	Sum512 := func(msg []byte) []byte {
		res := sha512.New()
		res.Write(msg)
		hash := res.Sum(nil)
		return []byte(hash)
	}

	digest := Sum512(data)

	curveOrderByteSize := pubkey.Curve.Params().P.BitLen() / 8

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(signature[:curveOrderByteSize])
	s.SetBytes(signature[curveOrderByteSize:])

	return ecdsa.Verify(pubkey, digest[:], r, s)
}

func ReadPrivateKeyFromHex(Dhex string) (*ecdsa.PrivateKey, error) {
	c := nums.P512()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func ReadPrivateKeyFromHexX(Dhex string) (*eccrypt512.PrivateKey, error) {
	c := nums.P512()
	d, err := hex.DecodeString(Dhex)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(d)
	params := c.Params()
	one := new(big.Int).SetInt64(1)
	n := new(big.Int).Sub(params.N, one)
	if k.Cmp(n) >= 0 {
		return nil, errors.New("privateKey's D is overflow.")
	}
	priv := new(eccrypt512.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func WritePrivateKeyToHex(key *ecdsa.PrivateKey) string {
	d := key.D.Bytes()
	if n := len(d); n < 64 {
		d = append(zeroByteSlice()[:128-n], d...)
	}
	c := []byte{}
	c = append(c, d...)
	return hex.EncodeToString(c)
}

func ReadPublicKeyFromHex(Qhex string) (*ecdsa.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 129 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 128 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(ecdsa.PublicKey)
	pub.Curve = nums.P512()
	pub.X = new(big.Int).SetBytes(q[:64])
	pub.Y = new(big.Int).SetBytes(q[64:])
	return pub, nil
}

func ReadPublicKeyFromHexX(Qhex string) (*eccrypt512.PublicKey, error) {
	q, err := hex.DecodeString(Qhex)
	if err != nil {
		return nil, err
	}
	if len(q) == 129 && q[0] == byte(0x04) {
		q = q[1:]
	}
	if len(q) != 128 {
		return nil, errors.New("publicKey is not uncompressed.")
	}
	pub := new(eccrypt512.PublicKey)
	pub.Curve = nums.P512()
	pub.X = new(big.Int).SetBytes(q[:64])
	pub.Y = new(big.Int).SetBytes(q[64:])
	return pub, nil
}
func WritePublicKeyToHex(key *ecdsa.PublicKey) string {
	x := key.X.Bytes()
	y := key.Y.Bytes()
	if n := len(x); n < 64 {
		x = append(zeroByteSlice()[:64-n], x...)
	}
	if n := len(y); n < 64 {
		y = append(zeroByteSlice()[:64-n], y...)
	}
	c := []byte{}
	c = append(c, x...)
	c = append(c, y...)
	return hex.EncodeToString(c)
}

func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

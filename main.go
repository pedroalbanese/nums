// Parameters for the Microsoft Nothing Up My Sleeve Elliptic curves
package nums

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once
var p256 *elliptic.CurveParams
var p512 *elliptic.CurveParams

func initP256() {
	p256 = new(elliptic.CurveParams)
	p256.P, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43", 16)
	p256.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffe43c8275ea265c6020ab20294751a825", 16)
	p256.B, _ = new(big.Int).SetString("25581", 16)
	p256.Gx, _ = new(big.Int).SetString("01", 16)
	p256.Gy, _ = new(big.Int).SetString("696f1853c1e466d7fc82c96cceeedd6bd02c2f9375894ec10bf46306c2b56c77", 16)
	p256.BitSize = 256
}

func P256() elliptic.Curve {
	initonce.Do(initP256)
	return p256
}

func initP512() {
	p512 = new(elliptic.CurveParams)
	p512.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7", 16)
	p512.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b3ca4fb94e7831b4fc258ed97d0bdc63b568b36607cd243ce153f390433555d", 16)
	p512.B, _ = new(big.Int).SetString("1d99b", 16)
	p512.Gx, _ = new(big.Int).SetString("02", 16)
	p512.Gy, _ = new(big.Int).SetString("1c282eb23327f9711952c250ea61ad53fcc13031cf6dd336e0b9328433afbdd8cc5a1c1f0c716fdc724dde537c2b0adb00bb3d08dc83755b205cc30d7f83cf28", 16)
	p512.BitSize = 256
}

func P512() elliptic.Curve {
	initonce.Do(initP512)
	return p512
}

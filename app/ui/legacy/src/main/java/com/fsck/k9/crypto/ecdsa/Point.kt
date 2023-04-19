package com.fsck.k9.crypto.ecdsa

import java.math.BigInteger

class Point(val x: BigInteger, val y: BigInteger, val curve:Curve){

    // override constructor
    constructor(x: BigInteger, y: BigInteger): this(x, y, Secp256k1)

    override fun toString(): String {
        return "X: $x \nY: $y"
    }
}

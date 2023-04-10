package com.fsck.k9.crypto.ecdsa

import java.math.BigInteger

class Point (val x: BigInteger, val y: BigInteger, val curve:Curve){
    override fun toString(): String {
        return "X: $x \nY: $y"
    }
}

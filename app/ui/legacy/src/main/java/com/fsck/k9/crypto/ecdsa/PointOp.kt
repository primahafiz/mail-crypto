package com.fsck.k9.crypto.ecdsa

import java.math.BigInteger

object PointOp {
    fun identitas (point: Point) : Point {
        return Point(point.curve.p, BigInteger.ZERO, point.curve)
    }
    fun ganda (point: Point) : Point {
        if (point.x == point.curve.p) {
            return point
        }

        return dot(point, point, tangent(point, point.curve), point.curve)
    }
    fun dot (p1: Point, p2: Point, m : BigInteger, curve: Curve) : Point {
        val v = (p1.y + curve.p - (m * p1.x) % curve.p) % curve.p
        val x = (m*m + curve.p - p1.x + curve.p - p2.x) % curve.p
        val y = (curve.p - (m*x) % curve.p + curve.p - v) % curve.p
        return Point(x, y, curve)
    }
    fun tangent (point: Point, curve: Curve) : BigInteger {
        return bagi(point.x * point.x*BigInteger.valueOf(3)+curve.a, point.y * BigInteger.valueOf(2), curve.p)
    }
    fun bagi (num : BigInteger, dom : BigInteger, prime: BigInteger) : BigInteger {
        val inverseDen = dom.modInverse(prime)
        return kali(num % prime, inverseDen, prime)
    }
    fun kali (a : BigInteger, b : BigInteger, prime: BigInteger) : BigInteger {
        return (a * b) % prime
    }
}

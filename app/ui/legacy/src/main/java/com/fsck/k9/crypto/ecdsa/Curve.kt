package com.fsck.k9.crypto.ecdsa
import java.math.BigInteger

abstract class Curve {
    abstract val p : BigInteger
    abstract val n: BigInteger
    abstract val a : BigInteger
    abstract val b: BigInteger
    /**
     * X cord of the generator point -> G.
     */
    abstract val x : BigInteger

    /**
     * Y cord of the generator point -> G.
     */
    abstract val y: BigInteger
    val g: Point
        get() = Point(x,y,this)

    /**
     * Identitas
     * (PRIME MODULUS, 0)
     */
    val identitas: Point
        get() =  Point(p,  BigInteger.ZERO, this)

    /**
     * Penambahan 2 titik pada curve.
     */
    fun add_two_points (p1: Point, p2:Point): Point{
        if (p1.x == p) {
            return p2
        } else if (p2.x == p) {
            return p1
        }

        if (p1.x == p2.x) {
            if (p1.y == p2.y) {
                return PointOp.ganda(p1)
            }
            return PointOp.identitas(p1)
        }

        val m = PointOp.bagi(p1.y + p - p2.y, p1.x + p - p2.x, p)
        return PointOp.dot(p1, p2, m, this)
    }

    /**
     * Operasi dot sebanyak n
     */
    fun dot_n_times (g : Point, n : BigInteger) : Point {
        var r = identitas
        var q = g
        var m = n

        while (m != BigInteger.ZERO) {


            if (m and BigInteger.valueOf(1) != 0.toBigInteger()) {
                r = add_two_points(r, q)
            }

            m = m shr 1

            if (m != 0.toBigInteger()) {
                q = PointOp.ganda(q)
            }

        }

        return r
    }
}

package com.fsck.k9.crypto.keccak

import com.fsck.k9.crypto.ecdsa.Hasher
import java.math.BigInteger
import kotlin.math.min

object Keccak256: Hasher {
    private val BIT_65 = BigInteger.ONE shl 64
    private val MAX_64_BITS = BIT_65 - BigInteger.ONE

    private const val BLOCK_SIZE = 136  // r
    private const val DIGEST_SIZE = 32  // d
    private const val ROUNDS = 24

    override fun hash(plain: ByteArray): ByteArray {
        val state = IntArray(200)
        // convert plain from byte array to unsigned int array
        val uMessage = IntArray(plain.size) { plain[it].toInt() and 0xFF }

        var offset = 0
        var blockSize = 0

        // absorbing
        while (offset < uMessage.size) {
            blockSize = min(uMessage.size - offset, BLOCK_SIZE)
            for (i in 0 until blockSize) {
                state[i] = state[i] xor uMessage[offset + i]
            }
            offset += blockSize

            if (blockSize == BLOCK_SIZE) {
                doKeccakF(state)
                blockSize = 0
            }
        }

        // padding
        state[blockSize] = state[blockSize] xor 0x01
        state[BLOCK_SIZE - 1] = state[BLOCK_SIZE - 1] xor 0x80
        doKeccakF(state)

        // squeezing
        val digest = ByteArray(DIGEST_SIZE)
        offset = 0
        while (offset < DIGEST_SIZE) {
            blockSize = min(DIGEST_SIZE - offset, BLOCK_SIZE)
            for (i in 0 until blockSize) {
                digest[offset + i] = state[i].toByte()
            }
            offset += blockSize

            if (offset < DIGEST_SIZE) {
                doKeccakF(state)
            }
        }

        return digest
    }

    private fun doKeccakF(state: IntArray) {
        val lState = Array(5) { Array(5) { BigInteger.ZERO } }

        for (i in 0 until 5) {
            for (j in 0 until 5) {
                val temp = IntArray(8)
                state.copyInto(temp, 0, (i + 5 * j) * 8, (i + 5 * j) * 8 + 8)
                lState[i][j] = convertFromLETo64(temp)
            }
        }

        // keccak rounds
        var lfsrState = 1
        for (round in 0 until ROUNDS) {
            // theta
            val c = arrayOfNulls<BigInteger>(5)
            for (i in 0 until 5) {
                c[i] = lState[i][0].xor(lState[i][1]).xor(lState[i][2]).xor(lState[i][3]).xor(lState[i][4])
            }

            val d = arrayOfNulls<BigInteger>(5)
            for (i in 0 until 5) {
                d[i] = c[(i + 4) % 5]!!.xor(c[(i + 1) % 5]!!.leftRotate64(1))
            }

            for (i in 0 until 5) {
                for (j in 0 until 5) {
                    lState[i][j] = lState[i][j].xor(d[i]!!)
                }
            }

            // rho and pi
            var x = 1
            var y = 0
            var current = lState[x][y]
            for (i in 0 until ROUNDS) {
                // update x, y, current, and lState
                val temp = x
                x = y
                y = (2 * temp + 3 * y) % 5

                val shiftValue = current
                current = lState[x][y]

                lState[x][y] = shiftValue.leftRotate64Safely((i + 1) * (i + 2) / 2)
            }

            // chi
            for (j in 0 until 5) {
                val t = arrayOfNulls<BigInteger>(5)
                for (i in 0 until 5) {
                    t[i] = lState[i][j]
                }

                for (i in 0 until 5) {
                    val invertVal = t[(i + 1) % 5]!!.xor(MAX_64_BITS)
                    lState[i][j] = t[i]!!.xor(invertVal.and(t[(i + 2) % 5]!!))
                }
            }

            // iota
            for (i in 0 until 7) {
                lfsrState = (lfsrState shl 1 xor (lfsrState shr 7) * 0x71) % 256
                val bitPosition = (1 shl i) - 1
                if (lfsrState and 2 != 0) {
                    lState[0][0] = lState[0][0].xor(BigInteger.ONE shl bitPosition)
                }
            }
        }

        // reset state
        for (i in state.indices) {
            state[i] = 0
        }

        for (i in 0 until 5) {
            for (j in 0 until 5) {
                val temp = convertFrom64ToLE(lState[i][j])
                temp.copyInto(state, (i + 5 * j) * 8)
            }
        }
    }

    private fun convertFromLETo64(input: IntArray): BigInteger {
        val result = input.map { it.toString(16) }.map { if (it.length == 2) it else "0$it" }.reversed().joinToString("")
        return BigInteger(result, 16)
    }

    private fun convertFrom64ToLE(input: BigInteger): IntArray {
        val result = input.toString(16)
        val resultPadded = "0".repeat(16 - result.length) + result
        val temp = IntArray(8) { ((7 - it) * 2).let {pos ->
            resultPadded.substring(pos, pos + 2).toInt(16)
            }
        }
        return temp
    }

    private fun BigInteger.leftRotate64Safely(rotate: Int) = leftRotate64(rotate % 64)

    private fun BigInteger.leftRotate64(rotate: Int) = (this shr (64 - rotate)).add(this shl rotate).mod(BIT_65)
}

//fun main() {
//    val plain = "Hello, world!".toByteArray()
//    val digest = Keccak256.hash(plain)
//    println(digest)
//    println(digest.joinToString("") { String.format("%02x", it) })
//}

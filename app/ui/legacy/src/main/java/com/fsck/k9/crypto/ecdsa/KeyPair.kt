package com.fsck.k9.crypto.ecdsa

import java.math.BigInteger
import java.security.SecureRandom

class KeyPair (val publicKey : Point, val privateKey: BigInteger){
    companion object Generator {
        fun generate(curve: Curve) : KeyPair{
            val privateKey = generateRandom32BytePrivateKey() % curve.p
            val publicKey = curve.dot_n_times(curve.g, privateKey)
            return KeyPair(publicKey, privateKey)
        }

        fun generate (privateKey: BigInteger, curve: Curve) : KeyPair {
            val publicKey = curve.dot_n_times(curve.g, privateKey)
            return KeyPair(publicKey, privateKey)
        }

        fun generateRandom32BytePrivateKey() : BigInteger{
            val privateKeyBytes = ByteArray(32)
            SecureRandom().nextBytes(privateKeyBytes)
            return (BigInteger(privateKeyBytes).abs())
        }
    }
}

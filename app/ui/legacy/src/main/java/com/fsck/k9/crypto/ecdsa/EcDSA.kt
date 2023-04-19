package com.fsck.k9.crypto.ecdsa


import com.fsck.k9.crypto.keccak.Keccak256
import java.math.BigInteger
import java.security.SecureRandom

object EcDSA {

    fun getRandomK(n:BigInteger): BigInteger{
        var rand = BigInteger(256, SecureRandom())
        while (rand >= n || rand <= BigInteger.ONE){
            rand = BigInteger(256, SecureRandom())
        }
        return rand
    }

    fun sign(keyPair: KeyPair, message: ByteArray, hasher:Hasher): Signature{
        val md = BigInteger(1,hasher.hash((message)))
        val g = keyPair.publicKey.curve.g
        val n = keyPair.publicKey.curve.n
        val k = getRandomK(n)%n
        val p1 = g.curve.dot_n_times(g, k)
        val r = p1.x

        // Mulai dari awal jika nilai r adalah nol
        if (r == BigInteger.ZERO){
            sign(keyPair,message, hasher)
        }

        val s = (k.modInverse(n)) * (md + (keyPair.privateKey * r)% n)%n
        // Mulai dari awal jika nilai s adalah nol
        if (s == BigInteger.ZERO) {
            sign(keyPair, message, hasher)
        }

        return Signature(r, s)
    }

    fun sign(keyPair: KeyPair, message: String, hasher: Hasher): Signature{
        val message_byte = message.toByteArray()
        return sign(keyPair,message_byte,hasher)
    }
    fun sign(privateKey: String, message: String): Signature{
        val message_byte = message.toByteArray()
        val SK = BigInteger(privateKey)
        val keyPair = KeyPair.generate(SK, Secp256k1)
        return sign(keyPair,message_byte, Keccak256)
    }
    fun verify(PK: Point, message: ByteArray, hasher: Hasher, signature: Signature): Boolean{
        val md = BigInteger(1,hasher.hash((message)))
        val g = PK.curve.g
        val n = PK.curve.n
        val curve = PK.curve
        val r = signature.r
        val s = signature.s

        if (r < BigInteger.ONE || r > n - BigInteger.ONE) {
            return false
        }

        if (s < BigInteger.ONE || s > n - BigInteger.ONE) {
            return false
        }

        val c = s.modInverse(n)
        val u1 = (md * c) % n
        val u2 = (r * c) % n
        val temp1 = curve.dot_n_times(g,u1)
        val temp2 = curve.dot_n_times(PK,u2)
        val xy = curve.add_two_points(temp1,temp2)
        val v = xy.x % n

        return v == r
    }

    fun verify(PK: Point, message: ByteArray, signature: Signature): Boolean{
        val hasher = Keccak256
        val md = BigInteger(1,hasher.hash((message)))
        val g = PK.curve.g
        val n = PK.curve.n
        val curve = PK.curve
        val r = signature.r
        val s = signature.s

        if (r < BigInteger.ONE || r > n - BigInteger.ONE) {
            return false
        }

        if (s < BigInteger.ONE || s > n - BigInteger.ONE) {
            return false
        }

        val c = s.modInverse(n)
        val u1 = (md * c) % n
        val u2 = (r * c) % n
        val temp1 = curve.dot_n_times(g,u1)
        val temp2 = curve.dot_n_times(PK,u2)
        val xy = curve.add_two_points(temp1,temp2)
        val v = xy.x % n

        return v == r
    }

    fun main(){
//        val randomKeys = KeyPair.generate(Secp256k1)
//        val privateKey = BigInteger("1241521345235")
        val fromPrivateKey = KeyPair.generate((Secp256k1))
        System.out.println(fromPrivateKey.privateKey)
        System.out.println(fromPrivateKey.publicKey)

        val data = byteArrayOf(0x13, 0x37)
        val signature1 = sign(fromPrivateKey, data, Sha256)
        System.out.println(signature1.r)
        System.out.println(signature1.s)

        val publicKey = Point(fromPrivateKey.publicKey.x,fromPrivateKey.publicKey.y, Secp256k1)
        val signature = Signature(signature1.r,signature1.s)
        val isValid = verify(publicKey, data, Sha256, signature)
        System.out.println(isValid)
    }
}

package com.fsck.k9.crypto.ecdsa

interface Hasher {
    fun hash(message: ByteArray): ByteArray
}

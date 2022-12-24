@file:Suppress("NOTHING_TO_INLINE", "ClassName", "Unused", "OPT_IN_USAGE", "FunctionName")

package cryptojs
@JsModule("crypto-js")
@JsNonModule

external object CryptoJS {
    object lib {
        abstract class Base<T : Base<T>> {
            fun mixIn(properties: dynamic): T
            fun clone(): T
            abstract class CompanionObject<T : Base<T>> {
                fun create(): T
            }
        }
        abstract class WordArray : Base<WordArray> {
            val words: IntArray
            val sigBytes: Int
            override fun toString(): String
            fun toString(encoder: enc.Encoder): String
            fun concat(wordArray: WordArray): WordArray
            fun clamp()
            companion object {
                fun create(words: IntArray = definedExternally, sigBytes: Int = definedExternally): WordArray
                fun random(nBytes: Int): WordArray
            }
        }
        open class BufferedBlockAlgorithm : Base<BufferedBlockAlgorithm> {
            fun reset()
            companion object : CompanionObject<BufferedBlockAlgorithm>
        }
        abstract class Hasher<T : Hasher<T>> : Base<T> {
            val cfg: dynamic = definedExternally
            val blockSize: Int = definedExternally
            fun reset()
            fun update(messageUpdate: String): T
            fun update(messageUpdate: WordArray): T
            fun finalize(messageUpdate: String = definedExternally): WordArray
            fun finalize(messageUpdate: WordArray): WordArray
            abstract class CompanionObject<T : Hasher<T>> {
                fun create(cfg: dynamic = definedExternally): T
            }
        }
        abstract class Cipher<T : Cipher<T>> : Base<T> {
            val cfg: dynamic = definedExternally
            val keySize: Int = definedExternally
            val ivSize: Int = definedExternally
            fun reset()
            fun process(dataUpdate: String): WordArray
            fun process(dataUpdate: WordArray): WordArray
            fun finalize(dataUpdate: String = definedExternally): WordArray
            fun finalize(dataUpdate: WordArray): WordArray
            abstract class CompanionObject<T : Cipher<T>> {
                fun createEncryptor(key: WordArray, cfg: dynamic = definedExternally): T
                fun createDecryptor(key: WordArray, cfg: dynamic = definedExternally): T
            }
        }
        abstract class StreamCipher<T : StreamCipher<T>> : Cipher<T> {
            val blockSize: Int = definedExternally
            abstract class CompanionObject<T : StreamCipher<T>> : Cipher.CompanionObject<T>
        }
        abstract class BlockCipherMode<T : BlockCipherMode<T>> : Base<T> {
            abstract class CompanionObject<T : BlockCipherMode<T>> {
                fun <S : Cipher<S>> create(ciper: S, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
                fun <S : Cipher<S>> createEncryptor(ciper: S, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
                fun <S : Cipher<S>> createDecryptor(ciper: S, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
                fun <S : Cipher<S>> create(ciper: Cipher.CompanionObject<S>, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
                fun <S : Cipher<S>> createEncryptor(ciper: Cipher.CompanionObject<S>, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
                fun <S : Cipher<S>> createDecryptor(ciper: Cipher.CompanionObject<S>, iv: IntArray): mode.BlockCipherModeBlockProcessor<T>
            }
        }
        abstract class BlockCipher<T : BlockCipher<T>> : Cipher<T> {
            val blockSize: Int = definedExternally
            abstract class CompanionObject<T : BlockCipher<T>> : Cipher.CompanionObject<T>
        }
        abstract class CipherParams : Base<CipherParams> {
            var ciphertext: WordArray = definedExternally
            var key: WordArray = definedExternally
            var iv: WordArray = definedExternally
            var salt: WordArray = definedExternally
            var algorithm: Cipher<*> = definedExternally
            var mode: BlockCipherMode<*> = definedExternally
            var padding: pad.Pad = definedExternally
            var blockSize: Int = definedExternally
            var formatter: format.Format = definedExternally
            override fun toString(): String
            fun toString(formatter: format.Format): String
            companion object {
                fun create(cipherParams: dynamic): CipherParams
            }
        }
        abstract class SerializableCipher<T : SerializableCipher<T>> : Base<T> {
            val cfg: dynamic = definedExternally
            abstract class CompanionObject {
                fun <T : Cipher<T>> encrypt(cipher: Cipher<T>, message: String, key: WordArray, cfg: dynamic = definedExternally): CipherParams
                fun <T : Cipher<T>> encrypt(cipher: Cipher<T>, message: WordArray, key: WordArray, cfg: dynamic = definedExternally): CipherParams
                fun <T : Cipher<T>> decrypt(cipher: Cipher<T>, ciphertext: String, key: WordArray, cfg: dynamic = definedExternally): WordArray
                fun <T : Cipher<T>> decrypt(cipher: Cipher<T>, ciphertext: CipherParams, key: WordArray, cfg: dynamic = definedExternally): WordArray
                fun <T : Cipher<T>> encrypt(cipher: Cipher.CompanionObject<T>, message: String, key: WordArray, cfg: dynamic = definedExternally): CipherParams
                fun <T : Cipher<T>> encrypt(cipher: Cipher.CompanionObject<T>, message: WordArray, key: WordArray, cfg: dynamic = definedExternally): CipherParams
                fun <T : Cipher<T>> decrypt(cipher: Cipher.CompanionObject<T>, ciphertext: String, key: WordArray, cfg: dynamic = definedExternally): WordArray
                fun <T : Cipher<T>> decrypt(cipher: Cipher.CompanionObject<T>, ciphertext: CipherParams, key: WordArray, cfg: dynamic = definedExternally): WordArray
            }
            companion object : CompanionObject
        }
        object PasswordBasedCipher : SerializableCipher<PasswordBasedCipher> {
            fun <T : Cipher<T>> encrypt(cipher: Cipher<T>, message: String, password: String, vfg: dynamic = definedExternally): CipherParams
            fun <T : Cipher<T>> encrypt(cipher: Cipher<T>, message: WordArray, password: String, vfg: dynamic = definedExternally): CipherParams
            fun <T : Cipher<T>> decrypt(cipher: Cipher<T>, ciphertext: String, password: String, vfg: dynamic = definedExternally): WordArray
            fun <T : Cipher<T>> decrypt(cipher: Cipher<T>, ciphertext: CipherParams, password: String, vfg: dynamic = definedExternally): WordArray
            fun <T : Cipher<T>> encrypt(cipher: Cipher.CompanionObject<T>, message: String, password: String, vfg: dynamic = definedExternally): CipherParams
            fun <T : Cipher<T>> encrypt(cipher: Cipher.CompanionObject<T>, message: WordArray, password: String, vfg: dynamic = definedExternally): CipherParams
            fun <T : Cipher<T>> decrypt(cipher: Cipher.CompanionObject<T>, ciphertext: String, password: String, vfg: dynamic = definedExternally): WordArray
            fun <T : Cipher<T>> decrypt(cipher: Cipher.CompanionObject<T>, ciphertext: CipherParams, password: String, vfg: dynamic = definedExternally): WordArray
        }
    }
    object enc {
        abstract class Encoder {
            fun stringify(wordArray: lib.WordArray): String
            fun parse(str: String): lib.WordArray
        }
        abstract class UrlSafeEncoder : Encoder {
            fun stringify(wordArray: lib.WordArray, urlSafe: Boolean): String
            fun parse(str: String, urlSafe: Boolean): lib.WordArray
        }
        object Hex : Encoder
        object Latin1 : Encoder
        object Utf8 : Encoder
        object Base64 : Encoder
        object Base64url : UrlSafeEncoder
        object Utf16 : Encoder
        object Utf16BE : Encoder
        object Utf16LE : Encoder
    }
    object algo {
        abstract class HMAC<T : lib.Hasher<T>> : lib.Base<T> {
            fun reset()
            fun update(messageUpdate: String): HMAC<T>
            fun update(messageUpdate: lib.WordArray): HMAC<T>
            fun finalize(messageUpdate: String = definedExternally): lib.WordArray
            fun finalize(messageUpdate: lib.WordArray): lib.WordArray
            companion object {
                fun <T : lib.Hasher<T>> create(hasher: lib.Hasher.CompanionObject<T>, key: String): HMAC<T>
                fun <T : lib.Hasher<T>> create(hasher: lib.Hasher.CompanionObject<T>, key: lib.WordArray): HMAC<T>
            }
        }
        abstract class SHA1 : lib.Hasher<SHA1> {
            companion object : CompanionObject<SHA1>
        }
        abstract class SHA224 : lib.Hasher<SHA224> {
            companion object : CompanionObject<SHA224>
        }
        abstract class SHA256 : lib.Hasher<SHA256> {
            companion object : CompanionObject<SHA256>
        }
        abstract class SHA3 : lib.Hasher<SHA3> {
            companion object : CompanionObject<SHA3>
        }
        abstract class SHA384 : lib.Hasher<SHA384> {
            companion object : CompanionObject<SHA384>
        }
        abstract class SHA512 : lib.Hasher<SHA512> {
            companion object : CompanionObject<SHA512>
        }
        abstract class RIPEMD160 : lib.Hasher<RIPEMD160> {
            companion object : CompanionObject<RIPEMD160>
        }
        abstract class MD5 : lib.Hasher<MD5> {
            companion object : CompanionObject<MD5>
        }
        abstract class PBKDF2 : lib.Base<PBKDF2> {
            val cfg: dynamic = definedExternally
            fun compute(password: String, salt: String): lib.WordArray
            fun compute(password: String, salt: lib.WordArray): lib.WordArray
            fun compute(password: lib.WordArray, salt: String): lib.WordArray
            fun compute(password: lib.WordArray, salt: lib.WordArray): lib.WordArray
            companion object {
                fun create(cfg: dynamic = definedExternally): PBKDF2
            }
        }
        abstract class EvpKDF : lib.Base<EvpKDF> {
            val cfg: dynamic = definedExternally
            fun compute(password: String, salt: String): lib.WordArray
            fun compute(password: String, salt: lib.WordArray): lib.WordArray
            fun compute(password: lib.WordArray, salt: String): lib.WordArray
            fun compute(password: lib.WordArray, salt: lib.WordArray): lib.WordArray
            companion object {
                fun create(cfg: dynamic = definedExternally): EvpKDF
            }
        }
        abstract class AES : lib.BlockCipher<AES> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<AES>
        }
        abstract class DES : lib.BlockCipher<DES> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<DES>
        }
        abstract class TripleDES : lib.BlockCipher<TripleDES> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<TripleDES>
        }
        abstract class RC4 : lib.BlockCipher<RC4> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<RC4>
        }
        abstract class RC4Drop : lib.BlockCipher<RC4Drop> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<RC4Drop>
        }
        abstract class Rabbit : lib.BlockCipher<Rabbit> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<Rabbit>
        }
        abstract class RabbitLegacy : lib.BlockCipher<RabbitLegacy> {
            fun encryptBlock(map: Map<Int, Int>, offset: Int)
            fun decryptBlock(map: Map<Int, Int>, offset: Int)
            companion object : CompanionObject<RabbitLegacy>
        }
    }
    fun SHA1(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA1(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA1(message: String, key: String): lib.WordArray
    fun HmacSHA1(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA1(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA1(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun SHA256(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA256(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA256(message: String, key: String): lib.WordArray
    fun HmacSHA256(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA256(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA256(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun SHA224(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA224(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA224(message: String, key: String): lib.WordArray
    fun HmacSHA224(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA224(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA224(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun SHA3(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA3(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA3(message: String, key: String): lib.WordArray
    fun HmacSHA3(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA3(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA3(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun SHA384(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA384(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA384(message: String, key: String): lib.WordArray
    fun HmacSHA384(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA384(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA384(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun SHA512(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun SHA512(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacSHA512(message: String, key: String): lib.WordArray
    fun HmacSHA512(message: String, key: lib.WordArray): lib.WordArray
    fun HmacSHA512(message: lib.WordArray, key: String): lib.WordArray
    fun HmacSHA512(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun RIPEMD160(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun RIPEMD160(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacRIPEMD160(message: String, key: String): lib.WordArray
    fun HmacRIPEMD160(message: String, key: lib.WordArray): lib.WordArray
    fun HmacRIPEMD160(message: lib.WordArray, key: String): lib.WordArray
    fun HmacRIPEMD160(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun MD5(message: String, cfg: dynamic = definedExternally): lib.WordArray
    fun MD5(message: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun HmacMD5(message: String, key: String): lib.WordArray
    fun HmacMD5(message: String, key: lib.WordArray): lib.WordArray
    fun HmacMD5(message: lib.WordArray, key: String): lib.WordArray
    fun HmacMD5(message: lib.WordArray, key: lib.WordArray): lib.WordArray
    fun PBKDF2(password: String, salt: String, cfg: dynamic = definedExternally): lib.WordArray
    fun PBKDF2(password: String, salt: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun PBKDF2(password: lib.WordArray, salt: String, cfg: dynamic = definedExternally): lib.WordArray
    fun PBKDF2(password: lib.WordArray, salt: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun EvpKDF(password: String, salt: String, cfg: dynamic = definedExternally): lib.WordArray
    fun EvpKDF(password: String, salt: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    fun EvpKDF(password: lib.WordArray, salt: String, cfg: dynamic = definedExternally): lib.WordArray
    fun EvpKDF(password: lib.WordArray, salt: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    abstract class CipherAlgorithm {
        fun encrypt(message: String, key: String, cfg: dynamic = definedExternally): lib.CipherParams
        fun encrypt(message: lib.WordArray, key: String, cfg: dynamic = definedExternally): lib.CipherParams
        fun encrypt(message: String, key: lib.WordArray, cfg: dynamic = definedExternally): lib.CipherParams
        fun encrypt(message: lib.WordArray, key: lib.WordArray, cfg: dynamic = definedExternally): lib.CipherParams
        fun decrypt(ciphertext: String, key: String, cfg: dynamic = definedExternally): lib.WordArray
        fun decrypt(ciphertext: lib.CipherParams, key: String, cfg: dynamic = definedExternally): lib.WordArray
        fun decrypt(ciphertext: String, key: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
        fun decrypt(ciphertext: lib.CipherParams, key: lib.WordArray, cfg: dynamic = definedExternally): lib.WordArray
    }
    object AES : CipherAlgorithm
    object DES : CipherAlgorithm
    object TripleDES : CipherAlgorithm
    object RC4 : CipherAlgorithm
    object RC4Drop : CipherAlgorithm
    object Rabbit : CipherAlgorithm
    object RabbitLegacy : CipherAlgorithm
    object x64 {
        class Word : lib.Base<Word> {
            companion object {
                fun create(high: Int, low: Int): Word
            }
        }
        class WordArray  : lib.Base<WordArray> {
            fun toX32(): lib.WordArray
            companion object {
                fun create(words: Word, sigBytes: Int): WordArray
            }
        }
    }
    object mode {
        abstract class BlockCipherModeBlockProcessor<T : lib.BlockCipherMode<T>> : lib.BlockCipherMode<T> {
            fun processBlock(words: IntArray, offset: Int)
        }
        abstract class CBC : lib.BlockCipherMode<CBC> {
            companion object : CompanionObject<CBC>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
        abstract class CFB : lib.BlockCipherMode<CFB> {
            companion object : CompanionObject<CFB>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
        abstract class CTR : lib.BlockCipherMode<CTR> {
            companion object : CompanionObject<CTR>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
        abstract class CTRGladman : lib.BlockCipherMode<CTRGladman> {
            companion object : CompanionObject<CTRGladman>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
        abstract class ECB : lib.BlockCipherMode<ECB> {
            companion object : CompanionObject<ECB>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
        abstract class OFB : lib.BlockCipherMode<OFB> {
            companion object : CompanionObject<OFB>
            abstract class Encryptor : BlockCipherModeBlockProcessor<Encryptor> {
                companion object : CompanionObject<Encryptor>
            }
            abstract class Decryptor : BlockCipherModeBlockProcessor<Decryptor> {
                companion object : CompanionObject<Decryptor>
            }
        }
    }
    object pad {
        abstract class Pad {
            fun pad(data: lib.WordArray, blockSize: Int)
            fun unpad(data: lib.WordArray)
        }
        object Pkcs7 : Pad
        object AnsiX923 : Pad
        object Iso10126 : Pad
        object Iso97971 : Pad
        object NoPadding : Pad
        object ZeroPadding : Pad
    }
    object format {
        abstract class Format {
            fun stringify(cipherParams: lib.CipherParams): String
            fun parse(input: String): lib.CipherParams
        }
        object OpenSSL : Format
        object Hex : Format
    }
    object kdf {
        object OpenSSL {
            fun <T : lib.Hasher<T>> execute(password: String, keySize: Int, ivSize: Int, salt: String = definedExternally, hasher: lib.Hasher<T>): lib.CipherParams
            fun <T : lib.Hasher<T>> execute(password: String, keySize: Int, ivSize: Int, salt: String = definedExternally, hasher: lib.Hasher.CompanionObject<T> = definedExternally): lib.CipherParams
            fun <T : lib.Hasher<T>> execute(password: String, keySize: Int, ivSize: Int, salt: lib.WordArray, hasher: lib.Hasher<T>): lib.CipherParams
            fun <T : lib.Hasher<T>> execute(password: String, keySize: Int, ivSize: Int, salt: lib.WordArray, hasher: lib.Hasher.CompanionObject<T> = definedExternally): lib.CipherParams
        }
    }

}

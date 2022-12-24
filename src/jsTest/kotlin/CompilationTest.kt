@file:Suppress("UNUSED_VARIABLE")
import cryptojs.CryptoJS
import js.core.jso
import kotlin.test.Test

class CompilationTest {

    @Test
    fun wordArrayCompilation() {
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.lib.WordArray.create()
        val wordArray1: CryptoJS.lib.WordArray =
            CryptoJS.lib.WordArray.create(intArrayOf("00010203".toInt(16), "04050607".toInt(16)))
        val wordArray2: CryptoJS.lib.WordArray =
            CryptoJS.lib.WordArray.create(intArrayOf("00010203".toInt(16), "04050607".toInt(16)), 6)
        val string0: String = "" + wordArray0
        val string1: String = wordArray1.toString()
        val string2: String = wordArray1.toString(CryptoJS.enc.Utf8)
        val concatWordArray: CryptoJS.lib.WordArray = wordArray0.concat(wordArray1)
        val unit: Unit = wordArray2.clamp()
        val clone: CryptoJS.lib.WordArray = wordArray0.clone()
        val randomWordArray: CryptoJS.lib.WordArray = CryptoJS.lib.WordArray.random(16)
    }

    @Test
    fun hexCompilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Hex.parse("16aef614")
        val str: String = CryptoJS.enc.Hex.stringify(wordArray)
    }

    @Test
    fun latin1Compilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Latin1.parse("16aef614")
        val str: String = CryptoJS.enc.Latin1.stringify(wordArray)
    }

    @Test
    fun utf8Compilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Utf8.parse("16aef614")
        val str: String = CryptoJS.enc.Utf8.stringify(wordArray)
    }

    @Test
    fun base64Compilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Base64.parse("16aef614")
        val str: String = CryptoJS.enc.Base64.stringify(wordArray)
    }

    @Test
    fun base64UrlCompilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Base64url.parse("16aef614")
        val str: String = CryptoJS.enc.Base64url.stringify(wordArray)
    }

    @Test
    fun utf16Compilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Utf16.parse("16aef614")
        val str: String = CryptoJS.enc.Utf16.stringify(wordArray)
    }

    @Test
    fun utf16BECompilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Utf16BE.parse("16aef614")
        val str: String = CryptoJS.enc.Utf16BE.stringify(wordArray)
    }

    @Test
    fun utf16LECompilation() {
        val wordArray: CryptoJS.lib.WordArray = CryptoJS.enc.Utf16LE.parse("16aef614")
        val str: String = CryptoJS.enc.Utf16LE.stringify(wordArray)
    }

    @Test
    fun bufferedBlockAlgorithmCompilation() {
        val bufferedBlockAlgorithm: CryptoJS.lib.BufferedBlockAlgorithm = CryptoJS.lib.BufferedBlockAlgorithm.create()
        val unit: Unit = bufferedBlockAlgorithm.reset()
        val clone: CryptoJS.lib.BufferedBlockAlgorithm = bufferedBlockAlgorithm.clone()
    }

    @Test
    fun hasherCompilation() {
        val hasher0: CryptoJS.lib.Hasher<*> = CryptoJS.algo.SHA256.create()
        val unit: Unit = hasher0.reset()
        val hasher1: CryptoJS.lib.Hasher<*> = hasher0.update("message")
        val hasher2: CryptoJS.lib.Hasher<*> = hasher0.update(CryptoJS.lib.WordArray.create())
        val hash0: CryptoJS.lib.WordArray = hasher0.finalize()
        val hash1: CryptoJS.lib.WordArray = hasher1.finalize("message")
        val hash2: CryptoJS.lib.WordArray = hasher2.finalize(CryptoJS.lib.WordArray.create())
        val block: Int = hasher0.blockSize
    }

    @Test
    fun hmacCompilation() {
        val hmacHasher0: CryptoJS.algo.HMAC<*> = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, "key")
        val hmacHasher1: CryptoJS.algo.HMAC<*> = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, CryptoJS.lib.WordArray.create())
        val unit: Unit = hmacHasher0.reset()
        val hmacHasher2: CryptoJS.algo.HMAC<*> = hmacHasher0.update("Hi")
        val hmacHasher3: CryptoJS.algo.HMAC<*> = hmacHasher0.update(CryptoJS.lib.WordArray.create())
        val hmac0: CryptoJS.lib.WordArray = hmacHasher0.finalize()
        val hmac1: CryptoJS.lib.WordArray = hmacHasher0.finalize("Hello")
        val hmac2: CryptoJS.lib.WordArray = hmacHasher0.finalize(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun cipherCompilation() {
        val cipher0: CryptoJS.lib.Cipher<*> = CryptoJS.algo.AES.createEncryptor(CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val cipher1: CryptoJS.lib.Cipher<*> = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val unit: Unit = cipher0.reset()
        val wordArray0: CryptoJS.lib.WordArray = cipher0.process("data")
        val wordArray1: CryptoJS.lib.WordArray = cipher1.process(CryptoJS.lib.WordArray.create())
        val encrypted0: CryptoJS.lib.WordArray = cipher0.finalize()
        val encrypted1: CryptoJS.lib.WordArray = cipher0.finalize("data")
        val encrypted2: CryptoJS.lib.WordArray = cipher0.finalize(CryptoJS.lib.WordArray.create())
        val keySize: Int = cipher0.keySize
        val ivSize: Int = cipher0.ivSize
    }

    @Test
    fun blockCipherModeCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.lib.BlockCipherMode<*> = CryptoJS.mode.CBC.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.lib.BlockCipherMode<*> = CryptoJS.mode.CBC.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.lib.BlockCipherMode<*> = CryptoJS.mode.CBC.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
    }

    @Test
    fun cbcCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CBC.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CBC.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CBC.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CBC.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun ctrCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTR.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTR.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTR.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTR.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun ctrGladmanCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTRGladman.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTRGladman.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTRGladman.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CTRGladman.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun ecbCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.ECB.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.ECB.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.ECB.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.ECB.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun ofbCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.OFB.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.OFB.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.OFB.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.OFB.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun cfbCompilation() {
        val cipher = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
        val mode0: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CFB.createEncryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode1: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CFB.createDecryptor(cipher, CryptoJS.lib.WordArray.create().words)
        val mode2: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CFB.Encryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val mode3: CryptoJS.mode.BlockCipherModeBlockProcessor<*> = CryptoJS.mode.CFB.Decryptor.create(cipher, CryptoJS.lib.WordArray.create().words)
        val unit0: Unit = mode0.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit1: Unit = mode1.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit2: Unit =mode2.processBlock(CryptoJS.lib.WordArray.create().words, 5)
        val unit3: Unit = mode3.processBlock(CryptoJS.lib.WordArray.create().words, 5)
    }

    @Test
    fun pkcs7Compilation() {
        val pad: Unit = CryptoJS.pad.Pkcs7.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.Pkcs7.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun ansiX923Compilation() {
        val pad: Unit = CryptoJS.pad.AnsiX923.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.AnsiX923.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun iso10126Compilation() {
        val pad: Unit = CryptoJS.pad.Iso10126.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.Iso10126.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun iso97971Compilation() {
        val pad: Unit = CryptoJS.pad.Iso97971.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.Iso97971.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun noPaddingCompilation() {
        val pad: Unit = CryptoJS.pad.NoPadding.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.NoPadding.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun zeroPaddingCompilation() {
        val pad: Unit = CryptoJS.pad.ZeroPadding.pad(CryptoJS.lib.WordArray.create(), 4)
        val unpad: Unit = CryptoJS.pad.ZeroPadding.unpad(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun cipherParamsCompilation() {
        val cipherParams: CryptoJS.lib.CipherParams = CryptoJS.lib.CipherParams.create(jso {
            ciphertext = CryptoJS.lib.WordArray.create()
            key = CryptoJS.lib.WordArray.create()
            iv = CryptoJS.lib.WordArray.create()
            salt = CryptoJS.lib.WordArray.create()
            algorithm = CryptoJS.algo.AES
            mode = CryptoJS.mode.CBC
            padding = CryptoJS.pad.Pkcs7
            blockSize = 4
            formatter = CryptoJS.format.OpenSSL
        })
        val str0: String = "" +cipherParams
        val str1: String = cipherParams.toString()
        val str2: String = cipherParams.toString(CryptoJS.format.OpenSSL)
    }

    @Test
    fun openSSLFormatterCompilation() {
        val cipherParams = CryptoJS.lib.CipherParams.create(jso {
            ciphertext = CryptoJS.lib.WordArray.create()
            key = CryptoJS.lib.WordArray.create()
            iv = CryptoJS.lib.WordArray.create()
            salt = CryptoJS.lib.WordArray.create()
            algorithm = CryptoJS.algo.AES
            mode = CryptoJS.mode.CBC
            padding = CryptoJS.pad.Pkcs7
            blockSize = 4
            formatter = CryptoJS.format.OpenSSL
        })
        val str: String = CryptoJS.format.OpenSSL.stringify(cipherParams)
        val cipherParams1: CryptoJS.lib.CipherParams = CryptoJS.format.OpenSSL.parse(str)
    }

    @Test
    fun serializableCipherCompilation() {
        //val ciphertextParams0: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.lib.SerializableCipher.encrypt(cryptojs.CryptoJS.algo.AES, "sd", cryptojs.CryptoJS.lib.WordArray.create())
        //val ciphertextParams1: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.lib.SerializableCipher.encrypt(cryptojs.CryptoJS.algo.AES, cryptojs.CryptoJS.lib.WordArray.create(), cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertextParams2: CryptoJS.lib.CipherParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, "sd", CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertextParams3: CryptoJS.lib.CipherParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })

        //val plaintext1: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.lib.SerializableCipher.decrypt(cryptojs.CryptoJS.algo.AES, ciphertextParams0.toString(), cryptojs.CryptoJS.lib.WordArray.create())
        //val plaintext2: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.lib.SerializableCipher.decrypt(cryptojs.CryptoJS.algo.AES, ciphertextParams0, cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams3.toString(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams3, CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
    }

    @Test
    fun openSSLKdfCompilation() {
        val derivedParams0 = CryptoJS.kdf.OpenSSL.execute("Password", 256/32, 128/32)
        val derivedParams1 = CryptoJS.kdf.OpenSSL.execute("Password", 256/32, 128/32, "saltsalt")
        val derivedParams2 = CryptoJS.kdf.OpenSSL.execute("Password", 256/32, 128/32, "saltsalt", CryptoJS.algo.SHA1)
        val derivedParams3 = CryptoJS.kdf.OpenSSL.execute("Password", 256/32, 128/32, CryptoJS.lib.WordArray.create())
        val derivedParams4 = CryptoJS.kdf.OpenSSL.execute("Password", 256/32, 128/32, CryptoJS.lib.WordArray.create(), CryptoJS.algo.SHA1)
    }

    @Test
    fun passwordBasedCipherCompilation() {
        val ciphertextParams0: CryptoJS.lib.CipherParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, "message", "password")
        val ciphertextParams1: CryptoJS.lib.CipherParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, "message", "password", jso { format = CryptoJS.format.OpenSSL })
        val ciphertextParams2: CryptoJS.lib.CipherParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, CryptoJS.lib.WordArray.create(), "password")
        val ciphertextParams3: CryptoJS.lib.CipherParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, CryptoJS.lib.WordArray.create(), "password", jso { format = CryptoJS.format.OpenSSL })

        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams0.toString(), "password")
        val plaintext1: CryptoJS.lib.WordArray = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams0.toString(), "password", jso { format = CryptoJS.format.OpenSSL })
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams0, "password")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams0, "password", jso { format = CryptoJS.format.OpenSSL })
    }

    @Test
    fun sha1Compilation() {
        val sha1: CryptoJS.algo.SHA1 = CryptoJS.algo.SHA1.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA1("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA1(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA1("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA1("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA1(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA1(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun sha224Compilation() {
        val sha224: CryptoJS.algo.SHA224 = CryptoJS.algo.SHA224.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA224("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA224(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA224("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA224("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA224(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA224(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun sha256Compilation() {
        val sha256: CryptoJS.algo.SHA256 = CryptoJS.algo.SHA256.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA256("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA256(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA256("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA256("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA256(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA256(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun sha3Compilation() {
        val sha3: CryptoJS.algo.SHA3 = CryptoJS.algo.SHA3.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA3("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA3(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA3("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA3("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA3(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA3(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun sha384Compilation() {
        val sha384: CryptoJS.algo.SHA384 = CryptoJS.algo.SHA384.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA384("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA384(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA384("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA384("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA384(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA384(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun sha512Compilation() {
        val sha512: CryptoJS.algo.SHA512 = CryptoJS.algo.SHA512.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.SHA512("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.SHA512(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacSHA512("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacSHA512("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacSHA512(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacSHA512(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun ripemd160Compilation() {
        val ripemd160: CryptoJS.algo.RIPEMD160 = CryptoJS.algo.RIPEMD160.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.RIPEMD160("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.RIPEMD160(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacRIPEMD160("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacRIPEMD160("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacRIPEMD160(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacRIPEMD160(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun md5Compilation() {
        val md5: CryptoJS.algo.MD5 = CryptoJS.algo.MD5.create().clone()
        val wordArray0: CryptoJS.lib.WordArray = CryptoJS.MD5("message")
        val wordArray1: CryptoJS.lib.WordArray = CryptoJS.MD5(CryptoJS.lib.WordArray.create())
        val wordArray2: CryptoJS.lib.WordArray = CryptoJS.HmacMD5("message", "key")
        val wordArray3: CryptoJS.lib.WordArray = CryptoJS.HmacMD5("message", CryptoJS.lib.WordArray.create())
        val wordArray4: CryptoJS.lib.WordArray = CryptoJS.HmacMD5(CryptoJS.lib.WordArray.create(), "key")
        val wordArray5: CryptoJS.lib.WordArray = CryptoJS.HmacMD5(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
    }

    @Test
    fun pbkdf2Compilation() {
        val pbkdf20: CryptoJS.algo.PBKDF2 = CryptoJS.algo.PBKDF2.create()
        val pbkdf21: CryptoJS.algo.PBKDF2 = CryptoJS.algo.PBKDF2.create(jso {
            keySize = 128/32
            hasher = CryptoJS.algo.SHA1
            iterations = 1
        })
        val key0: CryptoJS.lib.WordArray = pbkdf20.compute("password", "salt")
        val key1: CryptoJS.lib.WordArray = pbkdf20.compute("password", CryptoJS.lib.WordArray.create())
        val key2: CryptoJS.lib.WordArray = pbkdf20.compute(CryptoJS.lib.WordArray.create(), "salt")
        val key3: CryptoJS.lib.WordArray = pbkdf20.compute(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())

        val key4: CryptoJS.lib.WordArray = CryptoJS.PBKDF2("password", "salt")
        val key5: CryptoJS.lib.WordArray = CryptoJS.PBKDF2("password", CryptoJS.lib.WordArray.create())
        val key6: CryptoJS.lib.WordArray = CryptoJS.PBKDF2(CryptoJS.lib.WordArray.create(), "salt")
        val key7: CryptoJS.lib.WordArray = CryptoJS.PBKDF2(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val key8: CryptoJS.lib.WordArray = CryptoJS.PBKDF2("password", "salt", jso { iterations = 1000 })
        val key9: CryptoJS.lib.WordArray = CryptoJS.PBKDF2("password", CryptoJS.lib.WordArray.create(), jso { iterations = 1000 })
        val key10: CryptoJS.lib.WordArray = CryptoJS.PBKDF2(CryptoJS.lib.WordArray.create(), "salt", jso { iterations = 1000 })
        val key11: CryptoJS.lib.WordArray = CryptoJS.PBKDF2(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iterations = 1000 })
    }

    @Test
    fun evpkdf2Compilation() {
        val evpkdf0: CryptoJS.algo.EvpKDF = CryptoJS.algo.EvpKDF.create()
        val evpkdf1: CryptoJS.algo.EvpKDF = CryptoJS.algo.EvpKDF.create(jso {
            keySize = 128/32
            hasher = CryptoJS.algo.SHA1
            iterations = 1
        })
        val key0: CryptoJS.lib.WordArray = evpkdf0.compute("password", "salt")
        val key1: CryptoJS.lib.WordArray = evpkdf0.compute("password", CryptoJS.lib.WordArray.create())
        val key2: CryptoJS.lib.WordArray = evpkdf0.compute(CryptoJS.lib.WordArray.create(), "salt")
        val key3: CryptoJS.lib.WordArray = evpkdf0.compute(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())

        val key4: CryptoJS.lib.WordArray = CryptoJS.EvpKDF("password", "salt")
        val key5: CryptoJS.lib.WordArray = CryptoJS.EvpKDF("password", CryptoJS.lib.WordArray.create())
        val key6: CryptoJS.lib.WordArray = CryptoJS.EvpKDF(CryptoJS.lib.WordArray.create(), "salt")
        val key7: CryptoJS.lib.WordArray = CryptoJS.EvpKDF(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val key8: CryptoJS.lib.WordArray = CryptoJS.EvpKDF("password", "salt", jso { iterations = 1000 })
        val key9: CryptoJS.lib.WordArray = CryptoJS.EvpKDF("password", CryptoJS.lib.WordArray.create(), jso { iterations = 1000 })
        val key10: CryptoJS.lib.WordArray = CryptoJS.EvpKDF(CryptoJS.lib.WordArray.create(), "salt", jso { iterations = 1000 })
        val key11: CryptoJS.lib.WordArray = CryptoJS.EvpKDF(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iterations = 1000 })
    }

    @Test
    fun aesCompilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt("message", "key")
        //val ciphertext1: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.AES.encrypt("message", cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(), "key")
        //val ciphertext3: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.AES.encrypt(cryptojs.CryptoJS.lib.WordArray.create(), cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt("message", CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })

        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0.toString(), "key")
        //val plaintext1: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.AES.decrypt(ciphertext0.toString(), cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0, "key")
        //val plaintext3: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.AES.decrypt(ciphertext0, cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.AES.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })

        val encryptor: CryptoJS.algo.AES = CryptoJS.algo.AES.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.AES = CryptoJS.algo.AES.createDecryptor(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun desCompilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt("message", "key")
        //val ciphertext1: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.DES.encrypt("message", cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt(CryptoJS.lib.WordArray.create(), "key")
        //val ciphertext3: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.DES.encrypt(cryptojs.CryptoJS.lib.WordArray.create(), cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt("message", CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.DES.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })


        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0.toString(), "key")
        //val plaintext1: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.DES.decrypt(ciphertext0.toString(), cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0, "key")
        //val plaintext3: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.DES.decrypt(ciphertext0, cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.DES.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { mode =  CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })

        val encryptor: CryptoJS.algo.DES = CryptoJS.algo.DES.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.DES = CryptoJS.algo.DES.createDecryptor(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun tripledesCompilation() {
        //val ciphertext0: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.TripleDES.encrypt("message", cryptojs.CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
        //val ciphertext1: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.TripleDES.encrypt("message", cryptojs.CryptoJS.lib.WordArray.create())
        //val ciphertext2: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.TripleDES.encrypt(cryptojs.CryptoJS.lib.WordArray.create(), cryptojs.CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
        //val ciphertext3: cryptojs.CryptoJS.lib.CipherParams = cryptojs.CryptoJS.TripleDES.encrypt(cryptojs.CryptoJS.lib.WordArray.create(), cryptojs.CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt("message", "800101010101010180010101010101018001010101010101")
        val ciphertext3: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt(CryptoJS.lib.WordArray.create(), "800101010101010180010101010101018001010101010101")
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt("message", "800101010101010180010101010101018001010101010101", jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt("message", "800101010101010180010101010101018001010101010101", jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"), jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.TripleDES.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"), jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })


        //val plaintext0: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.TripleDES.decrypt(ciphertext0.toString(), cryptojs.CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
        //val plaintext1: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.TripleDES.decrypt(ciphertext0.toString(), cryptojs.CryptoJS.lib.WordArray.create())
        //val plaintext2: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.TripleDES.decrypt(ciphertext0, cryptojs.CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
        //val plaintext3: cryptojs.CryptoJS.lib.WordArray = cryptojs.CryptoJS.TripleDES.decrypt(ciphertext0, cryptojs.CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4.toString(), "800101010101010180010101010101018001010101010101")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4, "800101010101010180010101010101018001010101010101")
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4.toString(), CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"), jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4.toString(), "800101010101010180010101010101018001010101010101", jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4, CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"), jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.TripleDES.decrypt(ciphertext4, "800101010101010180010101010101018001010101010101", jso { mode = CryptoJS.mode.ECB; padding = CryptoJS.pad.NoPadding })

        val encryptor: CryptoJS.algo.TripleDES = CryptoJS.algo.TripleDES.createEncryptor(CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
        val decryptor: CryptoJS.algo.TripleDES = CryptoJS.algo.TripleDES.createDecryptor(CryptoJS.enc.Hex.parse("800101010101010180010101010101018001010101010101"))
    }

    @Test
    fun rabbitCompilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt("message", "key")
        val ciphertext1: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt("message", CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt(CryptoJS.lib.WordArray.create(), "key")
        val ciphertext3: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt("message", CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.Rabbit.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })


        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0.toString(), "key")
        val plaintext1: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0, "key")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0, CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.Rabbit.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })

        val encryptor: CryptoJS.algo.Rabbit = CryptoJS.algo.Rabbit.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.Rabbit = CryptoJS.algo.Rabbit.createDecryptor(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun rabbitLegacyCompilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt("message", "key")
        val ciphertext1: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt("message", CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt(CryptoJS.lib.WordArray.create(), "key")
        val ciphertext3: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt("message", CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.RabbitLegacy.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })


        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0.toString(), "key")
        val plaintext1: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0, "key")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0, CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.RabbitLegacy.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })

        val encryptor: CryptoJS.algo.RabbitLegacy = CryptoJS.algo.RabbitLegacy.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.RabbitLegacy = CryptoJS.algo.RabbitLegacy.createDecryptor(CryptoJS.lib.WordArray.create())
    }

    @Test
    fun rc4Compilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt("message", "key")
        val ciphertext1: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt("message", CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(), "key")
        val ciphertext3: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt("message", CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })


        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0.toString(), "key")
        val plaintext1: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0, "key")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0, CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.RC4.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })

        val encryptor: CryptoJS.algo.RC4 = CryptoJS.algo.RC4.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.RC4 = CryptoJS.algo.RC4.createDecryptor(CryptoJS.lib.WordArray.create())
    }


    @Test
    fun rc4DropCompilation() {
        val ciphertext0: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt("message", "key")
        val ciphertext1: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt("message", CryptoJS.lib.WordArray.create())
        val ciphertext2: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt(CryptoJS.lib.WordArray.create(), "key")
        val ciphertext3: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create())
        val ciphertext4: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt("message", "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext5: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt("message", CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext6: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt(CryptoJS.lib.WordArray.create(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val ciphertext7: CryptoJS.lib.CipherParams = CryptoJS.RC4Drop.encrypt(CryptoJS.lib.WordArray.create(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })


        val plaintext0: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0.toString(), "key")
        val plaintext1: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create())
        val plaintext2: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0, "key")
        val plaintext3: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0, CryptoJS.lib.WordArray.create())
        val plaintext4: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0.toString(), "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext5: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0.toString(), CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext6: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0, "key", jso { iv = CryptoJS.lib.WordArray.create() })
        val plaintext7: CryptoJS.lib.WordArray = CryptoJS.RC4Drop.decrypt(ciphertext0, CryptoJS.lib.WordArray.create(), jso { iv = CryptoJS.lib.WordArray.create() })

        val encryptor: CryptoJS.algo.RC4Drop = CryptoJS.algo.RC4Drop.createEncryptor(CryptoJS.lib.WordArray.create())
        val decryptor: CryptoJS.algo.RC4Drop = CryptoJS.algo.RC4Drop.createDecryptor(CryptoJS.lib.WordArray.create())
    }

}

// Created by Mahmud. Thanks to MrMax(Github : https://github.com/MohamedX99) for helping.
// Helpers.js used.

// Only for Android usage, if anyone needs to use for other platform i hope you can manage to make it compatible ;)
// Send a PR as well :D

class Helpers {

    static #callbacks = new Map();

    static #cache = new Map();

    static #initialize = this.#initializer();

    static #initializer() {
        // Credits : https://github.com/iGio90/frida-onload, https://github.com/FrenchYeti/interruptor
        const linker = Process.getModuleByName(this.is64Bit() ? "linker64" : "linker");
        // https://android.googlesource.com/platform/bionic/+/master/linker/linker.cpp
        // void* do_dlopen(const char* name, int flags, const android_dlextinfo* extinfo, const void* caller_addr)
        let do_dlopen_ptr = null;
        // https://android.googlesource.com/platform/bionic/+/master/linker/linker_soinfo.cpp
        // void soinfo::call_constructors()
        let call_constructors_ptr = null;
        for (const symbol of linker.enumerateSymbols()) {
            const name = symbol.name;
            if (name.includes("do_dlopen"))
                do_dlopen_ptr = symbol.address;
            else if (name.includes("call_constructors"))
                call_constructors_ptr = symbol.address;
            if (do_dlopen_ptr !== null && call_constructors_ptr !== null)
                break;
        }
        if (do_dlopen_ptr !== null && call_constructors_ptr !== null) {
            const callbacks = this.#callbacks;
            let path = null;
            Interceptor.attach(do_dlopen_ptr, {
                onEnter(args) {
                    path = args[0].readUtf8String();
                }
            });
            Interceptor.attach(call_constructors_ptr, {
                onEnter(args) {
                    if (path !== null) {
                        const module = Process.findModuleByName(path);
                        if (module !== null) {
                            for (const key of callbacks.keys())
                                if (path.includes(key)) {
                                    try {
                                        callbacks.get(key)(module);
                                    } catch (e) {
                                        console.error(e);
                                    }
                                    callbacks.delete(key);
                                    break;
                                }
                        }
                        path = null;
                    }
                }
            });
            Interceptor.flush();
        } else
            console.error(`[*] do_dlopen  : ${do_dlopen_ptr}, call_constructors : ${call_constructors_ptr}`);
    }

    static onLibraryLoad(name, callback) {
        if (callback === undefined || callback === null)
            throw new Error(`No callback specified for ${name}`);
        this.#callbacks.set(name, callback);
    }

    static is64Bit() {
        return Process.arch.includes("64");
    }

    static getSpecificClassLoader(clazz) {
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                Java.use("java.lang.Class").forName(clazz, false, loader);
                return loader;
            } catch (e) {
                // ignore and continue
                continue;
            }
        }
        throw new Error(`${clazz} not found in any classloader`);
    }

    static getClassWrapper(clazz) {
        const cache = this.#cache;
        if (cache.has(clazz))
            return cache.get(clazz);
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                Java.use("java.lang.Class").forName(clazz, false, loader);
                const wrapper = Java.ClassFactory.get(loader).use(clazz);
                cache.set(clazz, wrapper);
                return wrapper;
            } catch (e) {
                // ignore and continue
                continue;
            }
        }
        throw new Error(`${clazz} not found`);
    }

    static getMethodWrapperExact(clazz, name, paramTypes, returnType) {
        const expectedParamTypesSignature = paramTypes.join(", ");
        for (const overload of this.getClassWrapper(clazz)[name].overloads)
            if (expectedParamTypesSignature === overload.argumentTypes.map(type => type.className).join(", ") && returnType === overload.returnType.className)
                return overload;
        throw new Error(`${clazz}.${name}(${expectedParamTypesSignature})${returnType} not found`)
    }

    // I failed to name this function programatically (out of ideas).
    static magic(fn, callback) {
        let retval;
        fn(function() {
            retval = callback.apply(this, arguments);
        });
        return retval;
    }

    static getMatched(array, property, contains) {
        return array.filter(value => contains.every(contain => value[property].includes(contain)));
    }
}

const name = "lib<whatever>.so";
Helpers.onLibraryLoad(name, function(module) {
    /*
     * typedef enum {
     *     MBEDTLS_CIPHER_NONE = 0,              Placeholder to mark the end of cipher-pair lists. 
     *     MBEDTLS_CIPHER_NULL,                  The identity stream cipher. 
     *     MBEDTLS_CIPHER_AES_128_ECB,           AES cipher with 128-bit ECB mode. 
     *     MBEDTLS_CIPHER_AES_192_ECB,           AES cipher with 192-bit ECB mode. 
     *     MBEDTLS_CIPHER_AES_256_ECB,           AES cipher with 256-bit ECB mode. 
     *     MBEDTLS_CIPHER_AES_128_CBC,           AES cipher with 128-bit CBC mode. 
     *     MBEDTLS_CIPHER_AES_192_CBC,           AES cipher with 192-bit CBC mode. 
     *     MBEDTLS_CIPHER_AES_256_CBC,           AES cipher with 256-bit CBC mode. 
     *     MBEDTLS_CIPHER_AES_128_CFB128,        AES cipher with 128-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_AES_192_CFB128,        AES cipher with 192-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_AES_256_CFB128,        AES cipher with 256-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_AES_128_CTR,           AES cipher with 128-bit CTR mode. 
     *     MBEDTLS_CIPHER_AES_192_CTR,           AES cipher with 192-bit CTR mode. 
     *     MBEDTLS_CIPHER_AES_256_CTR,           AES cipher with 256-bit CTR mode. 
     *     MBEDTLS_CIPHER_AES_128_GCM,           AES cipher with 128-bit GCM mode. 
     *     MBEDTLS_CIPHER_AES_192_GCM,           AES cipher with 192-bit GCM mode. 
     *     MBEDTLS_CIPHER_AES_256_GCM,           AES cipher with 256-bit GCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_ECB,      Camellia cipher with 128-bit ECB mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_ECB,      Camellia cipher with 192-bit ECB mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_ECB,      Camellia cipher with 256-bit ECB mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_CBC,      Camellia cipher with 128-bit CBC mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_CBC,      Camellia cipher with 192-bit CBC mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_CBC,      Camellia cipher with 256-bit CBC mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_CFB128,   Camellia cipher with 128-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_CFB128,   Camellia cipher with 192-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_CFB128,   Camellia cipher with 256-bit CFB128 mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_CTR,      Camellia cipher with 128-bit CTR mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_CTR,      Camellia cipher with 192-bit CTR mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_CTR,      Camellia cipher with 256-bit CTR mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_GCM,      Camellia cipher with 128-bit GCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_GCM,      Camellia cipher with 192-bit GCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_GCM,      Camellia cipher with 256-bit GCM mode. 
     *     MBEDTLS_CIPHER_DES_ECB,               DES cipher with ECB mode. 
     *     MBEDTLS_CIPHER_DES_CBC,               DES cipher with CBC mode. 
     *     MBEDTLS_CIPHER_DES_EDE_ECB,           DES cipher with EDE ECB mode. 
     *     MBEDTLS_CIPHER_DES_EDE_CBC,           DES cipher with EDE CBC mode. 
     *     MBEDTLS_CIPHER_DES_EDE3_ECB,          DES cipher with EDE3 ECB mode. 
     *     MBEDTLS_CIPHER_DES_EDE3_CBC,          DES cipher with EDE3 CBC mode. 
     *     MBEDTLS_CIPHER_AES_128_CCM,           AES cipher with 128-bit CCM mode. 
     *     MBEDTLS_CIPHER_AES_192_CCM,           AES cipher with 192-bit CCM mode. 
     *     MBEDTLS_CIPHER_AES_256_CCM,           AES cipher with 256-bit CCM mode. 
     *     MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG,  AES cipher with 128-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG,  AES cipher with 192-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG,  AES cipher with 256-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_CCM,      Camellia cipher with 128-bit CCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_CCM,      Camellia cipher with 192-bit CCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_CCM,      Camellia cipher with 256-bit CCM mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,  Camellia cipher with 128-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,  Camellia cipher with 192-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,  Camellia cipher with 256-bit CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_ARIA_128_ECB,          Aria cipher with 128-bit key and ECB mode. 
     *     MBEDTLS_CIPHER_ARIA_192_ECB,          Aria cipher with 192-bit key and ECB mode. 
     *     MBEDTLS_CIPHER_ARIA_256_ECB,          Aria cipher with 256-bit key and ECB mode. 
     *     MBEDTLS_CIPHER_ARIA_128_CBC,          Aria cipher with 128-bit key and CBC mode. 
     *     MBEDTLS_CIPHER_ARIA_192_CBC,          Aria cipher with 192-bit key and CBC mode. 
     *     MBEDTLS_CIPHER_ARIA_256_CBC,          Aria cipher with 256-bit key and CBC mode. 
     *     MBEDTLS_CIPHER_ARIA_128_CFB128,       Aria cipher with 128-bit key and CFB-128 mode. 
     *     MBEDTLS_CIPHER_ARIA_192_CFB128,       Aria cipher with 192-bit key and CFB-128 mode. 
     *     MBEDTLS_CIPHER_ARIA_256_CFB128,       Aria cipher with 256-bit key and CFB-128 mode. 
     *     MBEDTLS_CIPHER_ARIA_128_CTR,          Aria cipher with 128-bit key and CTR mode. 
     *     MBEDTLS_CIPHER_ARIA_192_CTR,          Aria cipher with 192-bit key and CTR mode. 
     *     MBEDTLS_CIPHER_ARIA_256_CTR,          Aria cipher with 256-bit key and CTR mode. 
     *     MBEDTLS_CIPHER_ARIA_128_GCM,          Aria cipher with 128-bit key and GCM mode. 
     *     MBEDTLS_CIPHER_ARIA_192_GCM,          Aria cipher with 192-bit key and GCM mode. 
     *     MBEDTLS_CIPHER_ARIA_256_GCM,          Aria cipher with 256-bit key and GCM mode. 
     *     MBEDTLS_CIPHER_ARIA_128_CCM,          Aria cipher with 128-bit key and CCM mode. 
     *     MBEDTLS_CIPHER_ARIA_192_CCM,          Aria cipher with 192-bit key and CCM mode. 
     *     MBEDTLS_CIPHER_ARIA_256_CCM,          Aria cipher with 256-bit key and CCM mode. 
     *     MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG,  Aria cipher with 128-bit key and CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG,  Aria cipher with 192-bit key and CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG,  Aria cipher with 256-bit key and CCM_STAR_NO_TAG mode. 
     *     MBEDTLS_CIPHER_AES_128_OFB,           AES 128-bit cipher in OFB mode. 
     *     MBEDTLS_CIPHER_AES_192_OFB,           AES 192-bit cipher in OFB mode. 
     *     MBEDTLS_CIPHER_AES_256_OFB,           AES 256-bit cipher in OFB mode. 
     *     MBEDTLS_CIPHER_AES_128_XTS,           AES 128-bit cipher in XTS block mode. 
     *     MBEDTLS_CIPHER_AES_256_XTS,           AES 256-bit cipher in XTS block mode. 
     *     MBEDTLS_CIPHER_CHACHA20,              ChaCha20 stream cipher. 
     *     MBEDTLS_CIPHER_CHACHA20_POLY1305,     ChaCha20-Poly1305 AEAD cipher. 
     *     MBEDTLS_CIPHER_AES_128_KW,            AES cipher with 128-bit NIST KW mode. 
     *     MBEDTLS_CIPHER_AES_192_KW,            AES cipher with 192-bit NIST KW mode. 
     *     MBEDTLS_CIPHER_AES_256_KW,            AES cipher with 256-bit NIST KW mode. 
     *     MBEDTLS_CIPHER_AES_128_KWP,           AES cipher with 128-bit NIST KWP mode. 
     *     MBEDTLS_CIPHER_AES_192_KWP,           AES cipher with 192-bit NIST KWP mode. 
     *     MBEDTLS_CIPHER_AES_256_KWP,           AES cipher with 256-bit NIST KWP mode.
     * } mbedtls_cipher_type_t;
     */

    // const mbedtls_cipher_info_t *mbedtls_cipher_info_from_type(const mbedtls_cipher_type_t cipher_type)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_info_from_type"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_info_from_type");
            console.log(`[*] Type : ${args[0].toInt32()}`);
        },
        onLeave(retval) {
            console.log("[*] onLeave : mbedtls_cipher_info_from_type");
        }
    });

    // int mbedtls_cipher_setup(mbedtls_cipher_context_t *ctx, const mbedtls_cipher_info_t *cipher_info)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_setup"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_setup");
            console.log(`[*] Type : ${args[1].readPointer().toInt32()}`);
        },
        onLeave(retval) {
            console.log("[*] onLeave : mbedtls_cipher_setup");
        }
    });

    /*
     * typedef enum {
     *     MBEDTLS_OPERATION_NONE = -1,
     *     MBEDTLS_DECRYPT = 0,
     *     MBEDTLS_ENCRYPT,
     * } mbedtls_operation_t;
     */

    // int mbedtls_cipher_setkey(mbedtls_cipher_context_t *ctx, const unsigned char *key, int key_bitlen, const mbedtls_operation_t operation)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_setkey"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_setkey");
            console.log(`[*] Key : ${args[1].readUtf8String()}`);
            console.log(`[*] Hexdump : ${hexdump2(args[1], 128)}`);
            console.log(`[*] Bitlen : ${args[2].toInt32()}`);
            console.log(`[*] Operation : ${args[3].toInt32()}`);
        },
        onLeave(retval) {
            console.log("[*] onLeave : mbedtls_cipher_setkey");
        }
    });

    /*
     * typedef enum {
     *     MBEDTLS_PADDING_PKCS7 = 0,     /**< PKCS7 padding (default).        
     *     MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         
     *     MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             
     *     MBEDTLS_PADDING_ZEROS,         /**< Zero padding (not reversible). 
     *     MBEDTLS_PADDING_NONE,          /**< Never pad (full blocks only).   
     * } mbedtls_cipher_padding_t;
     */

    // int mbedtls_cipher_set_padding_mode(mbedtls_cipher_context_t *ctx, mbedtls_cipher_padding_t mode)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_set_padding_mode"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_set_padding_mode");
            console.log(`[*] Mode : ${args[1].toInt32()}`);
        },
        onLeave(retval) {
            console.log("[*] onLeave : mbedtls_cipher_set_padding_mode");
        }
    });

    // int mbedtls_cipher_set_iv(mbedtls_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_set_iv"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_set_iv");
            console.log(`[*] IV : ${args[1].readUtf8String()}`);
            console.log(`[*] Len : ${args[2].toInt32()}`);
            console.log(`[*] Hexdump : ${hexdump2(args[1], args[2].toUInt32())}`);
        },
        onLeave(retval) {
            console.log("[*] onLeave : mbedtls_cipher_set_iv");
        }
    });

    // int mbedtls_cipher_update(mbedtls_cipher_context_t *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_update"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_update");
            console.log(`[*] Input : ${args[1].readUtf8String()}`);
            console.log(`[*] Len : ${args[2].toInt32()}`);
            console.log(`[*] Hexdump : ${hexdump2(args[1], args[2].toInt32())}`);
            this.buffer = args[3];
            this.len = args[4];
        },
        onLeave(retval) {
            console.log(`[*] Output : ${this.buffer.readUtf8String()}`);
            console.log(`[*] Len : ${this.len.readULong()}`);
            console.log(`[*] Hexdump : ${hexdump2(this.buffer, this.len.readULong())}`);
            console.log("[*] onLeave : mbedtls_cipher_update");
        }
    });

    // int mbedtls_cipher_finish(mbedtls_cipher_context_t *ctx, unsigned char *output, size_t *olen)
    Interceptor.attach(module.getExportByName("mbedtls_cipher_finish"), {
        onEnter(args) {
            console.log("[*] onEnter : mbedtls_cipher_finish");
            this.buffer = args[1];
            this.len = args[2];
        },
        onLeave(retval) {
            console.log(`[*] Output : ${this.buffer.readUtf8String()}`);
            console.log(`[*] Len : ${this.len.readULong()}`);
            console.log(`[*] Hexdump : ${hexdump2(this.buffer, this.len.readULong())}`);
            console.log("[*] onLeave : mbedtls_cipher_finish");
        }
    });
    Interceptor.flush();
});

function hexdump2(address, len) {
    return hexdump(address, {
        offset: 0,
        length: len,
        header: true
    });
}
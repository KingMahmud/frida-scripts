// Improved by Mahmud. Thanks to the other scripts out there!
// Helpers.js used.

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

function getMatchedSymbols(name, contains) {
    return Helpers.getMatched(Process.getModuleByName(name).enumerateSymbols(), "name", contains);
}

// Uncomment line 131, 139 and 160 if you want to log for a specific library
// const library = "lib<whatever>.so";
getMatchedSymbols("libart.so", ["art", "JNI", "RegisterNatives"]).forEach(symbol => {
    // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods)
    console.log(`[*] Intercepting ${symbol.name}`);
    Interceptor.attach(symbol.address, {
        onEnter(args) {
            const module = Process.getModuleByName(DebugSymbol.fromAddress(this.returnAddress).moduleName);
            const name = module.name;
            // if (name === library) {
            console.log(`[*] RegisterNatives`);
            console.log(`[*] Library : ${name}`);
            const clazz = args[1];
            console.log(`[*] Class : ${Java.vm.getEnv().getClassName(clazz)}`);
            const nMethods = parseInt(args[3]);
            console.log(`[*] Number of Methods : ${nMethods}`);
            console.log("[*] Methods : ");
            const methods = args[2];
            for (let i = 0; i < nMethods; i++) {
                const method = methods.add(i * Process.pointerSize * 3);
                const methodName = method.readPointer().readUtf8String();
                const signature = method.add(Process.pointerSize).readPointer().readUtf8String();
                const fnPtr = method.add(Process.pointerSize * 2).readPointer();
                const offset = fnPtr.sub(module.base);
                console.log(`[*] ${i + 1}.
[*] Method : ${methodName}
[*] Signature : ${methodName}${signature}
[*] FnPtr : ${fnPtr}
[*] Offset : ${offset}`);
            }
            // }
        }
    });
});
// Improved by Mahmud. Thanks to the other scripts out there!
// Helpers.js used.

class Helpers {

    static #cache = new Map();

    static #callbacks = new Map();

    static #initialize = this.initializer();

    static initializer() {
        // Credits : iGio90(https://github.com/iGio90/frida-onload), FrenchYeti(https://github.com/FrenchYeti/interruptor)
        const self = this;
        const linker = Process.findModuleByName(Process.arch.includes("64") ? "linker64" : "linker");
        if (linker !== null) {
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
                let path = null;
                Interceptor.attach(do_dlopen_ptr, {
                    onEnter(args) {
                        path = args[0].readUtf8String();
                    }
                });
                Interceptor.attach(call_constructors_ptr, {
                    onEnter(args) {
                        if (path !== null) {
                            const callbacks = self.#callbacks;
                            for (const key of callbacks.keys())
                                if (path.includes(key)) {
                                    const module = Process.findModuleByName(path);
                                    if (module !== null) {
                                        console.log(`[*] Library loaded : ${key}`);
                                        try {
                                            callbacks.get(key)(module);
                                        } catch (e) {
                                            console.error(e);
                                        }
                                        callbacks.delete(key);
                                    }
                                    break;
                                }
                            path = null;
                        }
                    }
                });
                Interceptor.flush();
            } else {
                console.error(`[*] do_dlopen  : ${do_dlopen_ptr}`);
                console.error(`[*] call_constructors : ${call_constructors_ptr}`);
            }
        } else
            console.error("[*] Failed to find linker");
    }

    static getMatched(array, property, must_contain) {
        return array.filter(value => must_contain.every(str => value[property].includes(str)));
    }

    static getSpecificClassLoader(clazz) {
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                loader.loadClass(clazz, false);
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
                loader.loadClass(clazz, false);
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
        throw new Error(`${clazz}#${name}(${expectedParamTypesSignature})${returnType} not found`)
    }

    // I failed to name this function programatically (out of ideas).
    static magic(func, callback) {
        let val;
        func(function() {
            val = callback.apply(this, arguments);
        });
        return val;
    }

    static onLibraryLoad(name, callback) {
        if (callback === undefined || callback === null)
            throw new Error(`No callback specified for ${name}`);
        this.#callbacks.set(name, callback);
    }
}

const library = "lib<whatever>.so";
Helpers.onLibraryLoad(library, function(module) {
    // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods)
    Interceptor.attach(Java.vm.getEnv().handle.readPointer().add(215 * Process.pointerSize).readPointer(), {
        onEnter(args) {
            if (!DebugSymbol.fromAddress(this.returnAddress).toString().includes(library))
                return;
            console.log("[*] env->RegisterNatives()");
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
        }
    });
});
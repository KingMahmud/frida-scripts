// Created by Mahmud.

/*
 * Usage : copy paste into your script, create Helper instance then access the functions..
 * Example of another util created using getMatched
 * function getMatchedSymbols(library_name, must_contain) {
 *    return Helpers.getMatched(Process.getModuleByName(library_name).enumerateSymbols(), "name", must_contain);
 * }
 * Example of using onLibraryLoad
 * Helpers.onLibraryLoad("libnative.so", function(module) {
 *     // module = frida module object for that library
 * });
 */

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

// ESM
// export Helpers;
// CommonJS
// module.exports = Helpers;
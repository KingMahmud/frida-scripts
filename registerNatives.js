// Improved by Mahmud. Thanks to the other scripts out there!
// Helpers.js used.

class Helpers {

    #cache = new Map();

    #ollcs = new Map();

    constructor() {
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
            for (const sym of linker.enumerateSymbols()) {
                const name = sym.name;
                if (name.includes("do_dlopen"))
                    do_dlopen_ptr = sym.address;
                else if (name.includes("call_constructors"))
                    call_constructors_ptr = sym.address;
                if (do_dlopen_ptr !== null && call_constructors_ptr !== null)
                    break;
            }
            if (do_dlopen_ptr !== null && call_constructors_ptr !== null) {
                let ddname = null;
                Interceptor.attach(do_dlopen_ptr, {
                    onEnter(args) {
                        ddname = args[0].readCString();
                    }
                });
                Interceptor.attach(call_constructors_ptr, {
                    onEnter(args) {
                        if (ddname !== null) {
                            const ollcs = self.#ollcs;
                            let name = null;
                            let callback = null;
                            for (const key of ollcs.keys())
                                if (ddname.includes(key)) {
                                    name = key;
                                    callback = ollcs.get(key);
                                    break;
                                }
                            if (name !== null && callback !== null) {
                                const module = Process.findModuleByName(ddname);
                                if (module !== null) {
                                    console.log(`[*] Library loaded : ${name}`);
                                    callback(module);
                                    // Nullify after callback has been called to avoid weird behaviors
                                    ddname = null;
                                    ollcs.delete(name);
                                }
                            }
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

    getMatched(array, property, must_contain) {
        return array.filter(value => must_contain.every(str => value[property].includes(str)));
    }

    getSpecificClassLoader(klass) {
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                loader.findClass(klass);
                return loader;
            } catch (e) {
                // ignore and continue
                continue;
            }
        }
        throw new Error(`${klass} not found in any classloader`);
    }

    getClassWrapper(klass) {
        const cache = this.#cache;
        if (cache.has(klass))
            return cache.get(klass);
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                loader.findClass(klass);
                const val = Java.ClassFactory.get(loader).use(klass);
                cache.set(klass, val);
                return val;
            } catch (e) {
                // ignore and continue
                continue;
            }
        }
        throw new Error(`${klass} not found`);
    }

    getMethodWrapperExact(klass, name, paramTypes, returnType) {
        const expectedParamTypesSignature = paramTypes.join(", ");
        for (const overload of this.getClassWrapper(klass)[name].overloads)
            if (expectedParamTypesSignature === overload.argumentTypes.map(type => type.className).join(", ") && returnType === overload.returnType.className)
                return overload;
        throw new Error(`${klass}#${name}(${expectedParamTypesSignature})${returnType} not found`)
    }

    // I failed to name this function programatically (out of ideas).
    magic(func, callback) {
        let val;
        func(function() {
            val = callback.apply(this, arguments);
        });
        return val;
    }

    onLibraryLoad(name, callback) {
        this.#ollcs.set(name, callback);
    }

    // Old implementation
    /*
    onLibraryLoad(name, callback) {
        Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
            onEnter(args) {
                let path = args[0].readCString();
                if (path.includes(name)) 
                    this.loaded = true;
            },
            onLeave(retval) {
                if (this.loaded) {
                    console.log(`[*] Library loaded : ${name}`);
                    callback(Process.findModuleByName(name));
                }
            }
        });
        Interceptor.flush();
    }
    */
}

const $Helpers = new Helpers();

const library = "libarm.so";

$Helpers.onLibraryLoad(library, function(module) {
    Interceptor.attach(Java.vm.getEnv().handle.readPointer().add(215 * Process.pointerSize).readPointer(), {
        // jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
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
                const methodName = method.readPointer().readCString();
                const signature = method.add(Process.pointerSize).readPointer().readCString();
                const fnPtr = method.add(Process.pointerSize * 2).readPointer();
                const offset = fnPtr.sub(module.base);
                console.log(`[*] ${i}.
Method : ${methodName}
Signature : ${methodName}${signature}
FnPtr : ${fnPtr}
Offset : ${offset}
                `);
            }
        }
    });
});

// Created by Mahmud.

/*

Usage : copy paste into your script, create Helper instance then access the functions..

Example of another util created using getMatched

function getMatchedSymbols(library_name, must_contain) {
    return _Helpers.getMatched(Process.getModuleByName(library_name).enumerateSymbols(), "name", must_contain);
}

Example of using onLibraryLoad

const _Helpers = new Helpers();

_Helpers.onLibraryLoad("libnative.so", function(module){
// module = frida module object for that library
});

*/

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
                if (name.includes("do_dlopen")) do_dlopen_ptr = sym.address;
                else if (name.includes("call_constructors")) call_constructors_ptr = sym.address;
                if (do_dlopen_ptr !== null && call_constructors_ptr !== null) break;
            }
            if (do_dlopen_ptr !== null && call_constructors_ptr !== null) {
                let name = null;
                Interceptor.attach(do_dlopen_ptr, function(args) {
                    name = args[0].readCString();
                });
                Interceptor.attach(call_constructors_ptr, function(args) {
                    if (name !== null) {
                        const ollcs = self.#ollcs;
                        let library_name = null;
                        let callback = null;
                        for (const key of ollcs.keys()) {
                            if (name.includes(key)) {
                                library_name = key;
                                callback = ollcs.get(key);
                                break;
                            }
                        }
                        if (library_name !== null && callback !== null) {
                            const module = Process.findModuleByName(name);
                            if (module !== null) {
                                console.log(`[*] Library loaded : ${library_name}`);
                                callback(module);
                                // nullify after callback has been called to avoid weird behaviors
                                name = null;
                                ollcs.delete(library_name);
                            }
                        }
                    }
                });
                Interceptor.flush();
            } else {
                console.error(`[*] do_dlopen  : ${do_dlopen_ptr}`);
                console.error(`[*] call_constructors : ${call_constructors_ptr}`);
            }
        } else console.error("[*] Failed to find linker");
    }

    getMatched(array, property, must_contain) {
        return array.filter(value => must_contain.every(str => value[property].includes(str)));
    }

    getSpecificClassLoader(must_contain) {
        for (const loader of Java.enumerateClassLoadersSync()) {
            try {
                loader.findClass(must_contain);
                return loader;
            } catch (e) {
                // ignore and continue
                continue;
            }
        }
        throw new Error(`${must_contain} not found in any classloader`);
    }

    getClassWrapper(klass) {
        const cache = this.#cache;
        if (cache.has(klass)) return cache.get(klass);
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

    // I failed to name the function programatically (out of ideas).
    magic(func, callback) {
        let val;
        func(function() {
            val = callback.bind(this).apply(callback, arguments);
        });
        return val;
    }

    onLibraryLoad(library_name, callback) {
        this.#ollcs.set(library_name, callback);
    }

    // Old implementation
    /*
    onLibraryLoad(library_name, callback) {
        Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
            onEnter: function(args) {
                let library_path = args[0].readCString();
                if (library_path.includes(library_name)) {
                    this.library_loaded = true;
                }
            },
            onLeave: function(retval) {
                if (this.library_loaded) {
                    console.log(`[*] Library loaded : ${library_name}`);
                    callback(Process.findModuleByName(library_name));
                }
            }
        });
        Interceptor.flush();
    }
    */
}

// const helpers = new Helpers();

// module.exports = helpers;
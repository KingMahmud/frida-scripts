/*
I did not create the "android_dlopen_ext" hook for checking if library loaded, i found it in some scripts i had.
So created a simple function for easy usage.

Credit goes to the person who written that.

Usage : 

Copy the onLibraryLoad function to your script and then : 

onLibraryLoad("yourlibname", () => {
// work
});

or

onLibraryLoad("yourlibname", function(){
// work
});
*/

function onLibraryLoad(library_name, callback) {
    let library_loaded = false;
    Interceptor.attach(Module.findExportByName(null, 'android_dlopen_ext'), {
        onEnter: (args) => {
            let library_path = args[0].readCString();
            if (library_path.includes(library_name)) {
                library_loaded = true;
            }
        },
        onLeave: (retval) => {
            if (library_loaded) {
                console.log(`[*] Library loaded : ${library_name}`);
                console.log("[*] Executing callback");
                callback();
                console.log("[*] Callback executed");
            }
        }
    });
}

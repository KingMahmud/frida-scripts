// Created by Mahmud.

console.log(`[*] Original PID : ${Process.id}`);

// pid_t getpid(void);
const getpid = new NativeFunction(Module.getExportByName("libc.so", "getpid"), "int", []);

// pid_t getppid(void);
const getppid = new NativeFunction(Module.getExportByName("libc.so", "getppid"), "int", []);

// int execve(const char *pathname, char *const argv[], char *const envp[])
Interceptor.attach(Module.getExportByName("libc.so", "execve"), {
    onEnter(args) {
        console.log(`[*] onEnter : execve(${args[0]}, ${args[1]}, ${args[2]})`);
        console.log(`[*] Current PID : ${getpid()}`);
        console.log(`[*] Parent PID : ${getppid()}`);
        console.log(`[*] Path : ${args[0].readUtf8String()}`);
        const argv = args[1];
        let i = 0;
        while (true) {
            const each = argv.add(i * Process.pointerSize).readPointer();
            if (each.isNull())
                break;
            else
                console.log(`[*] argv[${i++}] : ${each.readUtf8String()}`);
        }
        // Remove comments if you need to log envp array too.
        /*
        const envp = args[2];
        let j = 0;
        while (true) {
            const each = envp.add(j * Process.pointerSize).readPointer();
            if (each.isNull())
                break;
            else
                console.log(`[*] envp[${j++}] : ${each.readUtf8String()}`);
        }
        */
        console.log(`[*] Called from : \n${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
    },
    onLeave(retval) {
        console.log(`[*] return ${retval.toInt32()}`);
        console.log(`[*] onLeave : execve(...) => ${retval}`);
    }
});
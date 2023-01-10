// Created by Mahmud.

console.log(`[*] Original PID : ${Process.id}`);

// pid_t getpid(void);
const getpid = new NativeFunction(Module.findExportByName(null, "getpid"), "int", []);

// pid_t getppid(void);
const getppid = new NativeFunction(Module.findExportByName(null, "getppid"), "int", []);

// int execvpe(const char *file, char *const argv[], char *const envp[]);
Interceptor.attach(Module.findExportByName(null, "execvpe"), {
    onEnter(args) {
        console.log(`[*] onEnter : execvpe(${args[0]}, ${args[1]}, ${args[2]})`);
        console.log(`[*] Current PID : ${getpid()}`);
        console.log(`[*] Parent PID : ${getppid()}`);
        console.log(`[*] Path : ${args[0].readUtf8String()}`);
        const argv = args[1];
        let i = 0;
        while (true) {
            const each = argv.add(i * Process.pointerSize).readPointer().readUtf8String();
            if (each !== null) {
                console.log(`[*] argv[${i}] : ${each}`);
                i++;
            } else
                break;
        }
        /*
        const envp = args[2];
        let j = 0;
        while (true) {
            const each = envp.add(j * Process.pointerSize).readPointer().readUtf8String();
            if (each !== null) {
                console.log(`[*] envp[${j}] : ${each}`);
                j++;
            } else
                break;
        }
        */
        console.log(`[*] Called from : 
${Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n")}`);
    },
    onLeave(retval) {
        console.log(`[*] return ${retval.toInt32()}`);
        console.log(`[*] onLeave : execvpe(...) => ${retval}`);
    }
});
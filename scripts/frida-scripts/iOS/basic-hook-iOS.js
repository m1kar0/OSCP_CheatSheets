console.log("Script loaded!");

// Get the function address
var jailbrk_ptr = Module.findExportByName(null, "$s7DVIA_v232JailbreakDetectionViewControllerC12isJailbrokenSbyF");

if (jailbrk_ptr) {
    console.log("Found function at: " + jailbrk_ptr);
    Interceptor.attach(jailbrk_ptr, {
        onEnter: function(args) {
            console.log("Entered isJailbroken function");
        },
        onLeave: function(retval) {
            console.log("Original return value: " + retval.toInt32());
            retval.replace(0); // Force return false
            console.log("Modified return value to: false");
        }
    });

} else {
    console.log("Function not found! Check module or symbol name.");
    };
}

/*

This code changes the variable created on class init

*/

Java.perform(() => {

    //creating a string
    const newString = Java.use("java.lang.String").$new("Correct Credentials");

    let doLogin_clase = Java.use("com.android.insecurebankv2.DoLogin");

    doLogin_clase.$init.overload().implementation = function(){

    //this.$init();

    this.result.value = newString;


    console.log(this.result.value);

    }



});

/*

Different way of hookign and manipulating return values
*/




//

Java.perform(() => {

    const badenc1 =Java.use("sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_BadEncryption");

    badenc1.verify.implementation = function(){
    
    var ret_val = this.verify();

    console.log("the return value is: " + ret_val);
    
    //show normally returned variable
    return ret_val;
    // change to always return true
    // return true;
}


});




/**
 * 
 * This allows modifying the function input variables
 * 
 * 
 */

    Java.perform(function() {
        var TargetClass = Java.use("com.example.app.TargetClass");

        TargetClass.targetMethod.implementation = function(localVariableArg, anotherArg) {
            console.log("Original localVariableArg: " + localVariableArg);
            localVariableArg = "newValue"; // Modify the argument
            console.log("Modified localVariableArg: " + localVariableArg);

            // Call the original implementation with the modified argument
            return this.targetMethod(localVariableArg, anotherArg);
        };
    });/*
 * raptor_frida_android_enum.js - Java class/method enumerator
 * Copyright (c) 2017 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Frida.re JS functions to enumerate Java classes and methods 
 * declared in an iOS app. See https://www.frida.re/ and 
 * https://codeshare.frida.re/ for further information on this 
 * powerful tool.
 *
 * "We want to help others achieve interop through reverse
 * engineering" -- @oleavr
 *
 * Example usage:
 * # frida -U -f com.target.app -l raptor_frida_android_enum.js --no-pause
 *
 * Get the latest version at:
 * https://github.com/0xdea/frida-scripts/
 */

// enumerate all Java classes
function enumAllClasses()
{
	var allClasses = [];
	var classes = Java.enumerateLoadedClassesSync();

	classes.forEach(function(aClass) {
		try {
			var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
		}
		catch(err) {return;} // avoid TypeError: cannot read property 1 of null
		allClasses.push(className);
	});

	return allClasses;
}

// find all Java classes that match a pattern
function findClasses(pattern)
{
	var allClasses = enumAllClasses();
	var foundClasses = [];

	allClasses.forEach(function(aClass) {
		try {
			if (aClass.match(pattern)) {
				foundClasses.push(aClass);
			}
		}
		catch(err) {} // avoid TypeError: cannot read property 'match' of undefined
	});

	return foundClasses;
}

// enumerate all methods declared in a Java class
function enumMethods(targetClass)
{
	var hook = Java.use(targetClass);
	var ownMethods = hook.class.getDeclaredMethods();
	hook.$dispose;

	return ownMethods;
}

/*
 * The following functions were not implemented because deemed impractical:
 *
 * enumAllMethods() - enumerate all methods declared in all Java classes
 * findMethods(pattern) - find all Java methods that match a pattern
 *
 * See raptor_frida_ios_enum.js for a couple of ObjC implementation examples.
 */

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		// enumerate all classes
		/*
		var a = enumAllClasses();
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

		// find classes that match a pattern
		/*
		var a = findClasses(/password/i);
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

		// enumerate all methods in a class
		/*
		var a = enumMethods("com.target.app.PasswordManager")
		a.forEach(function(s) { 
			console.log(s); 
		});
		*/

	});
}, 0);
/*

 * Example usage:
 * # frida -U -F --runtime=v8 -l raptor_frida_android_trace.js --no-pause
 */

// generic trace
function trace(pattern)
{
	var type = (pattern.toString().indexOf("!") === -1) ? "java" : "module";

	if (type === "module") {

		// trace Module
		var res = new ApiResolver("module");
		var matches = res.enumerateMatchesSync(pattern);
		var targets = uniqBy(matches, JSON.stringify);
		targets.forEach(function(target) {
			traceModule(target.address, target.name);
		});

	} else if (type === "java") {

		// trace Java Class
		var found = false;
		Java.enumerateLoadedClasses({
			onMatch: function(aClass) {
				if (aClass.match(pattern)) {
					found = true;
					var className = aClass.match(/[L](.*);/)[1].replace(/\//g, ".");
					traceClass(className);
				}
			},
			onComplete: function() {}
		});

		// trace Java Method
		if (!found) {
			try {
				traceMethod(pattern);
			}
			catch(err) { // catch non existing classes/methods
				console.error(err);
			}
		}
	}
}

// find and trace all methods declared in a Java Class
function traceClass(targetClass)
{
	var hook = Java.use(targetClass);
	var methods = hook.class.getDeclaredMethods();
	hook.$dispose;

	var parsedMethods = [];
	methods.forEach(function(method) {
		parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
	});

	var targets = uniqBy(parsedMethods, JSON.stringify);
	targets.forEach(function(targetMethod) {
		traceMethod(targetClass + "." + targetMethod);
	});
}

// trace a specific Java Method
function traceMethod(targetClassMethod)
{
	var delim = targetClassMethod.lastIndexOf(".");
	if (delim === -1) return;

	var targetClass = targetClassMethod.slice(0, delim)
	var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)

	var hook = Java.use(targetClass);
	var overloadCount = hook[targetMethod].overloads.length;

	console.log("Tracing " + targetClassMethod + " [" + overloadCount + " overload(s)]");

	for (var i = 0; i < overloadCount; i++) {

		hook[targetMethod].overloads[i].implementation = function() {
			console.warn("\n*** entered " + targetClassMethod);

			// print backtrace
			// Java.perform(function() {
			//	var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
			//	console.log("\nBacktrace:\n" + bt);
			// });   

			// print args
			if (arguments.length) console.log();
			for (var j = 0; j < arguments.length; j++) {
				console.log("arg[" + j + "]: " + arguments[j]);
			}

			// print retval
			var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
			console.log("\nretval: " + retval);
			console.warn("\n*** exiting " + targetClassMethod);
			return retval;
		}
	}
}

// trace Module functions
function traceModule(impl, name)
{
	console.log("Tracing " + name);

	Interceptor.attach(impl, {

		onEnter: function(args) {

			// debug only the intended calls
			this.flag = false;
			// var filename = Memory.readCString(ptr(args[0]));
			// if (filename.indexOf("XYZ") === -1 && filename.indexOf("ZYX") === -1) // exclusion list
			// if (filename.indexOf("my.interesting.file") !== -1) // inclusion list
				this.flag = true;

			if (this.flag) {
				console.warn("\n*** entered " + name);

				// print backtrace
				console.log("\nBacktrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
						.map(DebugSymbol.fromAddress).join("\n"));
			}
		},

		onLeave: function(retval) {

			if (this.flag) {
				// print retval
				console.log("\nretval: " + retval);
				console.warn("\n*** exiting " + name);
			}
		}

	});
}

// remove duplicates from array
function uniqBy(array, key)
{
        var seen = {};
        return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
}

// usage examples
setTimeout(function() { // avoid java.lang.ClassNotFoundException

	Java.perform(function() {

		// trace("com.target.utils.CryptoUtils.decrypt");
		// trace("com.target.utils.CryptoUtils");
		// trace("CryptoUtils");
		// trace(/crypto/i);
		// trace("exports:*!open*");

	});   
}, 0);

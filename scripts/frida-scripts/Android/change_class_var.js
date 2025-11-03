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


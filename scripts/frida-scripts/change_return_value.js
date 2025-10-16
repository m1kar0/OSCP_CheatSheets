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




# Pentesting Android - Mobile

## Methodology



## ADB use

### controlling activities and intents

Android debug bridge is an in-built tool which a lot of functionality.

For exmaple if intent is formulated inside `MainActivity` class of `com.stego.saw` as

```java
        Bundle extras = getIntent().getExtras();
        if (extras == null) {
            finish();
            return;
        }
        if (!extras.getString("open").equalsIgnoreCase("sesame")) {
            finish();
            return;
        }
```

then to start it passing string value of `sesame` to the the variable `open`

```bash

adb shell am start -a android.intent.action.MAIN --es open "sesame" -n com.stego.saw/.MainActivity

```

### controlling permissions


For instance, some permissions like `SYSTEM_ALERT_WINDOW` are restricted by the system. To grant this permission, the following command can be issued:

```bash
adb shell appops set com.stego.saw SYSTEM_ALERT_WINDOW allow
```

## Setup

### Setup Burp proxy and CA



### Rooting

1. Select a GooglePlay x86 + API30
2. start your device and launch aeroot

```bash
# the emulator bin is located in your Android/Sdk/tools foolder
$ emulator -list-avds 
TO_BE_ROOTED_API_30
$ emulator -avd TO_BE_ROOTED_API_30 -qemu -s
$ adb devices
$ docker run --rm --network host ha0ris/aeroot daemon
$ adb shell id

#you need to see this
uid=0(root) gid=0(root) groups=0(root)
```

## FRIDA

### What is frida used for

1. Bypassing application integrity checks:
    Frida can be used to hook and modify function calls that check for device integrity or user authentication. For example, an app may check if it is running on a Russian device using System.getProperty("user.home"). With Frida, this check can be bypassed by modifying the return value of the function to always return "Russia".

2. Debugging and tracing function calls: 
    Frida allows developers to trace function calls, inspect arguments, and monitor return values. This is particularly useful for understanding the inner workings of an application, especially when the source code is not available. For instance, you can trace all Java methods of a specific class or monitor cryptographic functions.

3. Memory analysis and dumping: 
    Frida can be used to dump an application's memory, which can then be analyzed for sensitive information such as passwords, API keys, or unobfuscated strings. Tools like Fridump make this process straightforward.

    Intercepting and modifying network traffic: Frida can be used to defeat certificate pinning, allowing developers to inspect HTTPS traffic. This is useful for security testing and understanding how an app communicates with its backend servers.

4. Hooking native code: 
    Frida can also be used to hook into native code, allowing developers to inspect and modify the behavior of C or C++ functions. This is particularly useful for analyzing performance or security vulnerabilities in native libraries.

5. Dynamic analysis of Android applications:
    Frida enables dynamic analysis by allowing developers to inject scripts into running processes. This can be used to monitor file system access, inspect memory, or modify application behavior in real-time.

6. Automating tasks and bypassing security mechanisms: 
    Frida can be used to automate tasks such as bypassing login screens or modifying application logic. For example, a script can be written to hook a login verification function and always return a successful result.

### FRIDA setup

Once the device is rooted -> install frida server on it

#### DEVICE SIDE

```bash

# check device to know which frida to download
adb shell
getprop | grep abi

# upload correct frida to device
push frida_86_something /data/local/tmp/frida86

# in device 
adb shell
chmod 700 /data/local/tmp/frida86
./data/local/tmp/frida86
```

#### CLIENT SIDE

```bash
#WE NEED EXACTLY THOSE VERSION!!! -> compatibility with objection
pip3 install frida-tools==13.0
pip3 install frida==16.7.19

# on  check if frida seems any processes from device
frida-ps -Uai

# inject into process of interest
# ready to use templates of injections scripts can be found at https://github.com/0xdea/frida-scripts
frida -U --runtime=v8 -l hook.js -f app.process.test

```

### Objection SETUP


## Hacks

### DUMPING

By using rooted devices it is possible to dump so tasty secrets from the phone.

1. Keystore: The Keystore provides a "secure" location to store cryptographic keys, preventing unauthorized access.

```bash
# aeroot then do this
adb pull /data/misc/keystore .
```

### Objection USE

Objection (https://book.hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/frida-tutorial/objection-tutorial.html) can be used in conjunction with FRIDA to
facilitate and more easily attack and explore the runing apps.

For example, set some value to always true!

```bash

android hooking set return_value sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_BadEncryption.v
erify true


```

## FRIDA USE

## BUILD AND SIGN
first remove the original app

`adb uninstall com.android.insecurebankv2`

then sign using the uber signing tool while in the directory with the needed apks 

`uber-apk-signer --apks ./`


## Using objection

pip3 install objection



## Memory dumping

### dump all
Just dump everything and search

```bash

git clone https://github.com/rootbsd/fridump3.git

python3 fridump3.py -u -o DUMP/ [PROC_ID]

#you gonna get some output with lots of files *data
#use grep to get the secrets out of thm

# so u know lets suppose the login : GOOD_USER_BOY
grep -r ""

# output
ANDROID_EMU_gles_max_version_3_0 
TSYS 
BNDL
BNDL
GOOD_USER_BOY
VERY_SECURE_PASSWORD!
GL_EXT_robustness GL_OES_EGL_sy


```

### look for specific string

```bash

memory search GOOD_USER_BOY --string

```

## MobSF

```bash

sudo docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

```

## Drozer

Drozer is a mobile hacking framework that focuses on exported components, services and insecure permissions: 

* Activities
* Broadcast receivers
* Content providers
* Services

 that consists of client and server. Server is installed as drozer.apk onto the target device. Client can send various commands to it. The main goal is to simulate a malicious app with drozer server and send, for instance, malicious intents to the tested app.

```bash

adb install drozer-agent.apk
adb forward tcp:31415 tcp:31415
drozer console connect --server 127.0.0.1:31415

```

When connetion is established refer to this command list:

```text

run	    Executes a drozer module

list	Show a list of all drozer modules that can be executed in the current session. This hides modules that you do not have suitable permissions to run.

shell	Start an interactive Linux shell on the device, in the context of the Agent process.

cd	    Mounts a particular namespace as the root of session, to avoid having to repeatedly type the full name of a module.

clean	Remove temporary files stored by drozer on the Android device.
contributors

echo	Print text to the console.

exit	Terminate the drozer session.

help	Display help about a particular command or module.

load	Load a file containing drozer commands, and execute them in sequence.

module	Find and install additional drozer modules from the Internet.

permissions	Display a list of the permissions granted to the drozer Agent.

set	Store a value in a variable that will be passed as an environment variable to any Linux shells spawned by drozer.

unset	Remove a named variable that drozer passes to any Linux shells that it spawns.

```

To use drozer module type `run` and TAB to list them all.

### Analysis with drozer

1. identify attack surface

```bash

dz> run app.package.attacksurface com.zin.dvac

#feedback show some exported services
Attempting to run shell module
Attack Surface:
  4 activities exported
  3 broadcast receivers exported
  1 content providers exported
  2 services exported
    is debuggable

# lets dig deeper
```

2. see which activities are exported with null permissions and their controllable components

```bash

dz> run app.activity.info -a  com.zin.dvac -i
Attempting to run shell module
Package: com.zin.dvac
  com.zin.dvac.ChangePasswordActivity
    Permission: null
    Intent Filter:
      Actions:
        - android.intent.action.VIEW
      Categories:
        - android.intent.category.DEFAULT
        - android.intent.category.BROWSABLE
  com.zin.dvac.LoginActivity
    Permission: null
    Intent Filter:
      Actions:
        - android.intent.action.MAIN
      Categories:
        - android.intent.category.LAUNCHER
  com.zin.dvac.PasswordManagerActivity
    Permission: null
    Intent Filter:
      Actions:
        - android.intent.action.VIEW
      Categories:
        - android.intent.category.DEFAULT
        - android.intent.category.BROWSABLE
  com.zin.dvac.SecretFileActivity
    Permission: null



```
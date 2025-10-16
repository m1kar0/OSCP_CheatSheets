# BASH 

## Basics

* Initiate bash script like so

```bash

#!/bin/bash

echo hello;

```

This is called shebang indicating that it is bash script. Anyother shell can be included instead of bash, so pay attention to what is used within the target OS.

* Save script as `hello.sh` and Make script executable `chmod 777 hello.sh`. Permissions are given with `777` as it is easy to remember but not secure. So don't do it in any meaningful production environments.

* Arithmetics

```bash
# Addition
expr 2 + 3  # Output: 5

# Subtraction
expr 5 - 2  # Output: 3

# Multiplication
expr 2 \* 3  # Output: 6 (Note the backslash before the asterisk)

# Division
expr 10 / 2  # Output: 5

```

## Variables

* Variables are needed to make scripts dynamic

```bash

$0  name of bash script
$1 - $9 first nine variables within script
$#  number of arguments passed to script
$@  all arguments pased to bash script
$$	The process ID of the current script
$USER   The username of the user running the script
$HOSTNAME	The hostname of the machine
$RANDOM     A random number
$LINENO The current line number in the script

```

## User input

Use read with this with `-p` for prompt and `-s` for silent input.

```bash

#!/bin/bash

echo "yes or no?"

# just input line
read answer

# input with prompt
read -p 'May be ' answer

#silent input and prompt
read -sp 'May be yes ' answer

```

## Conditionals

### IF

Use this boiler plate as is to preserve all spaces and signs

```bash

if [ <some test> ]
then
  <perform an action>
fi

```

Common operators for `<some test>`

```bash 
!EXPRESSION             The EXPRESSION is false.
-n STRING	            STRING length is greater than zero
-z STRING	            The length of STRING is zero (empty)
STRING1 != STRING2	    STRING1 is not equal to STRING2
STRING1 = STRING2	    STRING1 is equal to STRING2
INTEGER1 -eq INTEGER2	INTEGER1 is equal to INTEGER2
INTEGER1 -ne INTEGER2	INTEGER1 is not equal to INTEGER2
INTEGER1 -gt INTEGER2	INTEGER1 is greater than INTEGER2
INTEGER1 -lt INTEGER2	INTEGER1 is less than INTEGER2
INTEGER1 -ge INTEGER2	INTEGER1 is greater than or equal to INTEGER 2
INTEGER1 -le INTEGER2	INTEGER1 is less than or equal to INTEGER 2
-d FILE	                FILE exists and is a directory
-e FILE	                FILE exists
-r FILE	                FILE exists and has read permission
-s FILE	                FILE exists and it is not empty
-w FILE	                FILE exists and has write permission
-x FILE	                FILE exists and has execute permission
```

#### Boolean operators in conditionals

```bash
# AND: executes if both tests are true
if [ <test 1> ] && [ <test 2> ]
then
  <perform an action>
fi

# OR: executes if one of tests is true
if [ <test 1> ] || [ <test 2> ]
then
  <perform an action>
fi

```

<b>ATTENTION</b>: in normal Command Line `&&` is placed between two commands to let second command execute only if the first executes and `||` does same but only if the first command fails

### FOR

Example 

``` bash
#oneliner
for ip in $(seq 1 10); do echo 10.11.1.$ip; done

#multi line
for ip in $(seq 1 10)
do
    echo 10.11.1.$ip
done
```

### While 

Boilerplate

```bash
while [ <some test> ]
do
  <perform an action>
done
```

Example 

```bash

#!/bin/bash

c=1

while [ $c -le 10 ]
do
  echo "10.11.1.$c"
  # increment counter :)
  ((c++))
done

```

## Functions

Boiler plate for function that takes and returns arguments

```bash

#!/bin/bash

a=5
b=6

sum (){

	echo $1 and $2

	c=$(expr $1 + $2)

	return $c
}

sum $a $b

# returns the value of last function
echo "last return is $?"


```

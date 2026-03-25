# PHP

## How to start

* CLI interactive mode `php -a`
* CLI run mode `php hello.php`
* save in web server folder and navigate to it

## Basics

* Decalare variable: `$var = "John Doe";`
* control structure:

```php
$a = 10;
$b = 20;
$c = $a + $b;

if ($c > 20) {
    echo "The result is greater than 20.";
} else {
    echo "The result is not greater than 20.";
}

//for loop

for ($i = 0; $i < 10; $i++) {
    echo $i . "\n";
}

//while 

$i = 0;
while ($i < 10) {
    echo $i . "\n";
    $i++;
}
```

* functions

```php
function say_hello($name) {
    echo "Hello, " . $name . "!";
}

say_hello("John Doe");


```

## $_GET

pass variables using the GET method in the URL, you can append them to the end of the URL as query parameters. The query parameters consist of a key-value pair, separated by an equal sign (=) and joined by an ampersand (&).

```html
<a href="example.php?name=John&age=30">Go to Example Page</a>

```

Backend code for receiver

```php

<?php
    $name = $_GET["name"];
    $age = $_GET["age"];
    echo "Hello, my name is " . $name . " and I am " . $age . " years old.";
?>

```

## $_REQUEST

`$_REQUEST` is a superglobal array in PHP that contains data from both the `$_GET` and `$_POST` arrays. The `$_REQUEST` array is used to access data from HTML forms or from the URL.

```php
<?php
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $username = $_REQUEST["username"];
        echo "Hello, " . $username;
    }
?>
```
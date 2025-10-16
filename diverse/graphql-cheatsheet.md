# GraphQL

## Query

```json

{
    "operationName":null,
    "variables":{},
    "query":"{\n  get {\n    insuredNumber\n    loginPhone {\n      number\n    }\n    loginEmail\n    isBetaTester\n }\n}\n"
}

```

## Mutation

```json

{
    "operationName":null,
    "variables":{},
    "query":"mutation {\n  address {\n    phone {\n      create(number: \"12345\", nature: LEG, mobile: false)\n    }\n  }\n}\n"
    }

```
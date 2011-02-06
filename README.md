Storing passwords securely in Haskell
=======================

If you need to store and verify passwords, there are many wrong ways to do it, most of them all too common. Some people store users' passwords in plain text. Then, when an attacker manages to get their hands on this file, they have the passwords for every user's account. One step up, but still wrong, is to simply hash all passwords with SHA1 or something. This is vulnerable to rainbow table and dictionary attacks. One step up from that is to hash the password along with a unique salt value. This is vulnerable to dictionary attacks, since guessing a password is very fast. The right thing to do is to use a slow hash function, to add some small but significant delay, that will be negligible for legitimate users but prohibitively expensive for someone trying to guess passwords by brute force. That is what this library does. It iterates a SHA256 hash, with a random salt, a few thousand times. This scheme is known as PBKDF1, and is generally considered secure; there is nothing innovative happening here.

There are two branches, which provide two different packages. The master branch
contains the pwstore-fast package, which uses the cryptohash library for fast
hashing. The purehaskell branch contains the pwstore-purehaskell package, which
has the exact same API, but with only pure Haskell dependencies. The pure
version is about 25 times slower, and is not recommended unless you have no
other choice, but it's still fast enough to be usable.

Installation
---------

Just get either the pwstore-fast or pwstore-purehaskell package via cabal-install:

    cabal-install pwstore-fast

[Haddoc docs are here.](http://hackage.haskell.org/packages/archive/pwstore-fast/1.0/doc/html/Crypto-PasswordStore.html)


Usage
-----

The API here is very simple. What you store are called *password hashes*.  They are strings (technically, ByteStrings) that look like this:

    "sha256|12|Ge9pg8a/r4JW356Uux2JHg==|Fdv4jchzDlRAs6WFNUarxLngaittknbaHFFc0k8hAy0="

Each password hash shows the algorithm, the strength (more on that later),
the salt, and the hashed-and-salted password. You store these on your server,
in a database, for when you need to verify a password. You make a password
hash with the 'makePassword' function. Here's an example:

    >>> makePassword "hunter2" 12
    "sha256|12|lMzlNz0XK9eiPIYPY96QCQ==|1ZJ/R3qLEF0oCBVNtvNKLwZLpXPM7bLEy/Nc6QBxWro="

This will hash the password "hunter2", with strength 12, which is a good default value. The strength here determines how long the hashing will take. When doing the hashing, we iterate the SHA256 hash function `2^strength` times, so increasing the strength by 1 makes the hashing take twice as long. When computers get faster, you can bump up the strength a little bit to compensate. You can strengthen existing password hashes with the `strengthenPassword` function. Note that `makePassword` needs to generate random numbers, so its return type is `IO ByteString`. If you want to avoid the IO monad, you can generate your own salt and pass it to `makePasswordSalt`.

Your strength value should not be less than 10, and 12 is a good default value at the time of this writing, in 2011.

Once you've got your password hashes, the second big thing you need to do with them is verify passwords against them. When a user gives you a password, you compare it with a password hash using the `verifyPassword` function:

    >>> verifyPassword "wrong guess" passwordHash
    False
    >>> verifyPassword "hunter2" passwordHash
    True

These two functions are really all you need. If you want to make existing password hashes stronger, you can use `strengthenPassword`. Just pass it an existing password hash and a new strength value, and it will return a new password hash with that strength value, which will match the same password as the old password hash.

Contributing
------

If you have any suggestions or patches, I would love to hear them. To make sure that your changes to the code work properly, you can run the test suite with

    runhaskell Tests.hs

The code is under the BSD3 license.

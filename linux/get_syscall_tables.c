// clang -O0 -std=c23 -ggdb get_syscall_tables.c -o get_syscall_tables && ./get_syscall_tables
//
// Resources:
// * https://github.com/torvalds/linux/tree/master/arch
// * https://sourceware.org/git/?p=glibc.git;a=tree;f=sysdeps/unix/sysv/linux;hb=HEAD
// * https://git.musl-libc.org/cgit/musl/tree/arch
// * https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define struct typedef struct

#define LINUX_ROOT "/home/tcadet/dev/open-source/linux/"
#define LINUX_ARCH_ROOT "/home/tcadet/dev/open-source/linux/arch/"

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#define DEFINE ((substring){ .bytes = "#define", .size = strlen("#define") })
#define substring(string) ((substring){ .bytes = string, .size = strlen(string) })

bool streq(char* a, char* b)
{
  return strcmp(a, b) == 0;
}

bool IsAlpha(char c)
{
  return (c >= 'a' && c <= 'z')
      || (c >= 'A' && c <= 'Z');
}

bool IsDigit(char c)
{
  return (c >= '0' && c <= '9');
}

char Capitalize(char c)
{
  if (c >= 'a' && c <= 'z')
  {
    c += ('A' - 'a');
  }
  return c;
}

enum arch_id
{
  X86_64_arch_id = 0,
  ARM_64_arch_id,
  RISCV_64_arch_id,
  X86_32_arch_id,
  ARM_32_arch_id,
  RISCV_32_arch_id,

  SIZE_arch_id
};

char* GetArchName(enum arch_id archId)
{
  char* name = 0;
  switch (archId)
  {
    case ARM_32_arch_id: name = "arm32"; break;
    case ARM_64_arch_id: name = "arm64"; break;
    case RISCV_32_arch_id: name = "riscv32"; break;
    case RISCV_64_arch_id: name = "riscv64"; break;
    case X86_32_arch_id: name = "x86_32"; break;
    case X86_64_arch_id: name = "x86_64"; break;
    default: assert(false); break;
  }
  return name;
}

struct
{
  char* bytes;
  size_t size;
}
substring;

bool Eq_string(substring a, substring b)
{
  bool eq = a.size == b.size;
  if (eq)
  {
    for (size_t i = 0; i < a.size && eq; ++i)
    {
      eq = eq && a.bytes[i] == b.bytes[i];
    }
  }
  return eq;
}

bool IsSpace(char c)
{
  return c == ' '
      || c == '\n'
      || c == '\t';
}

substring Trim_string(substring s)
{
  for (size_t i = 0; i < s.size && IsSpace(s.bytes[i]); ++i)
  {
    ++s.bytes;
    --s.size;
  }
  for (size_t i = s.size - 1; i != 0 && IsSpace(s.bytes[i]); --i)
  {
    --s.size;
  }
  return s;
}

bool Le_string(substring a, substring b)
{
  size_t i = 0;
  for (; i < a.size && i < b.size && a.bytes[i] == b.bytes[i]; ++i)
    ;

  bool le = (a.size == 0)
         || (a.bytes[i] < b.bytes[i])
         || (a.bytes[i] == b.bytes[i] && a.size <= b.size);

  return le;
}

unsigned long Hash_string(substring s)
{
  unsigned long hash = 5381;
  for (size_t i = 0; i < s.size; ++i)
  {
    int c = s.bytes[i];
    hash = 33*hash + c;
  }
  return hash;
}

enum htable_slot_state
{
  EMPTY_htable_slot_state = 0,
  OCCUPIED_htable_slot_state,
  REMOVED_htable_slot_state,
};

struct
{
  enum htable_slot_state state;
  substring key;
  int value[SIZE_arch_id];
  substring prototype;
}
htable_slot;

htable_slot Make_htable_slot(char* key, int value, enum arch_id arch)
{
  htable_slot slot = {0};
  slot.key.bytes = key;
  slot.key.size = strlen(key);
  for (size_t i = 0; i < SIZE_arch_id; ++i)
  {
    slot.value[i] = -1;
  }
  slot.value[arch] = value;
  return slot;
}

bool Le_htable_slot(htable_slot* a, htable_slot* b)
{
  return Le_string(a->key, b->key);
}

struct
{
  htable_slot* slots;
  size_t size;
  size_t capacity;
}
htable;

void Free_htable(htable* htable)
{
  free(htable->slots);
}

htable_slot* Get_htable(htable* htable, substring key)
{
  htable_slot* out = 0;
  unsigned long hash = Hash_string(key);
  for (size_t offset = 0; offset < htable->capacity; ++offset)
  {
    htable_slot* slot = &htable->slots[(hash + offset) % htable->capacity];
    if (slot->state == OCCUPIED_htable_slot_state && Eq_string(slot->key, key))
    {
      out = slot;
      break;
    }
    else if (slot->state == EMPTY_htable_slot_state)
    {
      break;
    }
  }

  return out;
}

htable_slot* Set_htable(htable* table, substring key)
{
  htable_slot* out = 0;
  unsigned long hash = Hash_string(key);
  for (size_t offset = 0; offset < table->capacity; ++offset)
  {
    htable_slot* slot = &table->slots[(hash + offset) % table->capacity];
    if (slot->state == EMPTY_htable_slot_state
          || slot->state == REMOVED_htable_slot_state)
    {
      slot->key = key;
      slot->state = OCCUPIED_htable_slot_state;
      out = slot;
      ++table->size;
      break;
    }
    else if (Eq_string(slot->key, key))
    {
      out = slot;
      break;
    }
  }

  if (!out)
  {
    htable newTable = {0};
    newTable.capacity = table->capacity ? 2*table->capacity : 16;
    newTable.slots = calloc(newTable.capacity, sizeof(htable_slot));

    for (size_t i = 0; i < table->capacity; ++i)
    {
      htable_slot* slot = &table->slots[i];
      if (slot->state == OCCUPIED_htable_slot_state)
      {
        htable_slot* newSlot = Set_htable(&newTable, slot->key);
        for (int archId = 0; archId < SIZE_arch_id; ++archId)
        {
          newSlot->value[archId] = slot->value[archId];
        }
      }
    }

    htable oldTable = *table;
    *table = newTable;
    Free_htable(&oldTable);

    out = Set_htable(table, key);
  }

  return out;
}

void Remove_htable_slot(htable* table, htable_slot* slot)
{
  if (slot)
  {
    slot->state = REMOVED_htable_slot_state;
    --(table->size);
  }
}

htable_slot* Remove_htable(htable* table, substring key)
{
  htable_slot* slot = Get_htable(table, key);
  Remove_htable_slot(table, slot);
  return slot;
}

struct
{
  htable_slot** items;
  size_t size;
  size_t capacity;
}
table;

void Free_table(table* t)
{
  free(t->items);
}

htable_slot** Push_table(table* table)
{
  if (table->size == table->capacity)
  {
    size_t newCapacity = table->capacity ? 2*table->capacity : 8;
    table->items = realloc(table->items, newCapacity*sizeof(*table->items));
    table->capacity = newCapacity;
  }
  ++table->size;
  return &table->items[table->size - 1];
}

void Quicksort_table(table* table_)
{
  if (table_->size > 1)
  {
    {
      // use middle of the table as pivot to avoid
      // running in O(n^2) if the table is already sorted
      size_t pivotIndex = table_->size/2;
      htable_slot* temp = table_->items[pivotIndex];
      table_->items[pivotIndex] = table_->items[0];
      table_->items[0] = temp;
    }

    htable_slot** pivot = &table_->items[0];
    size_t stop = table_->size;
    for (size_t i = 0; i < stop; ++i)
    {
      htable_slot** slot = &table_->items[i];
      if (!Le_htable_slot(*slot, *pivot))
      {
        htable_slot* temp = *slot;
        htable_slot** last = &table_->items[stop - 1];
        *slot = *last;
        *last = temp;
        --stop;
        --i;
      }
    }

    if (stop > 1)
    {
      htable_slot* temp = table_->items[stop-1];
      table_->items[stop-1] = *pivot;
      *pivot = temp;
      pivot = &table_->items[stop-1];
    }

    // printf("table at end of loop\n");
    // for (size_t index = 0; index < table_->size; ++index)
    // {
    //   substring key = table_->items[index]->key;
    //   printf("[%zu] = %.*s\n", index, (int)key.size, key.bytes);
    // }


    table a = {0};
    a.items = table_->items;
    a.size = pivot - table_->items;
    a.capacity = a.size;
    Quicksort_table(&a);

    if (pivot != table_->items + table_->size - 1)
    {
      table b = {0};
      b.items = pivot + 1;
      b.size = (table_->items + table_->size) - (pivot + 1);
      b.capacity = b.size;
      Quicksort_table(&b);
    }
  }
}

struct
{
  enum arch_id archId;

  char* inPath;
  char* outPath;
  int sysNrOffset;

  char* fileBytes;
  htable syscalls;
}
arch;

struct
{
  int sysNr;
  substring callingConvention;
  substring sysId;
}
syscall_number_line;

void Free_arch(arch* arch)
{
  free(arch->fileBytes);
  Free_htable(&arch->syscalls);
};

char* Read_file(const char* path)
{
  char* bytes = 0;
  FILE* file = fopen(path, "r");
  if (file)
  {
    assert(fseek(file, 0, SEEK_END) != -1);
    long size = ftell(file);
    assert(size != -1);
    rewind(file);

    bytes = (char*)calloc(size + 1, 1);

    assert(fread(bytes, 1, size, file) == size);

    fclose(file);
  }

  return bytes;
}

bool ReadUntil(char** bytes, char* delimiter, substring* out)
{
  bool delimiterMatches = false;

  if (bytes && *bytes) {
    char* checkpoint = *bytes;
    size_t delimiterSize = strlen(delimiter);
    while (**bytes)
    {
      delimiterMatches = true;
      for (size_t i = 0; i < delimiterSize && delimiterMatches; ++i)
      {
        delimiterMatches = (*bytes)[i] == delimiter[i];
      }

      if (delimiterMatches)
      {
        break;
      }

      (*bytes)++;
    }

    if (delimiterMatches)
    {
      if (out)
      {
        out->bytes = checkpoint;
        out->size = *bytes - checkpoint;
      }
      *bytes += delimiterSize;
    }
    else
    {
      *bytes = checkpoint;
    }
  }

  return delimiterMatches;
}

bool ReadUntilOneOf(char** bytes, char* delimiters, substring* out)
{
  bool delimiterMatches = false;

  if (bytes && *bytes) {
    char* checkpoint = *bytes;
    size_t delimiterSize = strlen(delimiters);
    while (**bytes)
    {
      for (size_t i = 0; i < delimiterSize && !delimiterMatches; ++i)
      {
        delimiterMatches = **bytes == delimiters[i];
      }

      if (delimiterMatches)
      {
        break;
      }

      (*bytes)++;
    }

    if (delimiterMatches)
    {
      if (out)
      {
        out->bytes = checkpoint;
        out->size = *bytes - checkpoint;
      }
      (*bytes)++;
    }
    else
    {
      *bytes = checkpoint;
    }
  }

  return delimiterMatches;
}

bool Read_int(char** bytes, int* out)
{
  bool success = false;
  if (bytes && *bytes)
  {
    int integer = 0;
    char* cursor = *bytes;
    while (*cursor)
    {
      char c = *cursor;
      if (c >= '0' && c <= '9')
      {
        success = true;
        integer *= 10;
        integer += c - '0';
      }
      else
      {
        break;
      }

      cursor++;
    }

    if (success)
    {
      *bytes = cursor;
      if (out)
      {
        *out = integer;
      }
    }
  }

  return success;
}

bool Read_syscall_number_line(char** bytes, syscall_number_line* outLine, enum arch_id archId)
{


  bool success = false;
  if (bytes && *bytes)
  {
    char* cursor = *bytes;
    syscall_number_line line = {0};
    success = Read_int(&cursor, &line.sysNr)
           && ReadUntil(&cursor, "\t", 0)
           // renameat is separated by a space (typo?) so we look for that too
           && ReadUntilOneOf(&cursor, "\t ", &line.callingConvention);
    // handle lines that end after the 3rd column
    char* cursor2 = cursor;
    success = success
           && ReadUntilOneOf(&cursor2, "\t\n", &line.sysId)
           && ReadUntil(&cursor, "\n", 0);

    // relevant kernel files for riscv:
    // 
    // scripts/syscall.tbl
    // arch/riscv/kernel/Makefile.syscalls
    // scripts/syscalltbl.sh
    // scripts/Makefile.asm-headers
    if (archId == RISCV_32_arch_id)
    {
      success = success && (
          Eq_string(line.callingConvention, substring("common"))
       || Eq_string(line.callingConvention, substring("32"))
       || Eq_string(line.callingConvention, substring("riscv"))
       || Eq_string(line.callingConvention, substring("memfd_secret")));
    }
    else if (archId == RISCV_64_arch_id)
    {
      success = success && (
          Eq_string(line.callingConvention, substring("common"))
       || Eq_string(line.callingConvention, substring("64"))
       || Eq_string(line.callingConvention, substring("riscv"))
       || Eq_string(line.callingConvention, substring("rlimit"))
       || Eq_string(line.callingConvention, substring("memfd_secret")));
    }
    else if (Eq_string(line.callingConvention, substring("csky"))
     || Eq_string(line.callingConvention, substring("nios2"))
     || Eq_string(line.callingConvention, substring("oabi"))
     || Eq_string(line.callingConvention, substring("or1k"))
     || Eq_string(line.callingConvention, substring("riscv"))
     || Eq_string(line.callingConvention, substring("x32"))
     || Eq_string(line.callingConvention, substring("arc")))
    {
      success = false;
    }

    if (success)
    {
      // x86_64 mseal is separated by several spaces so we clean that up
      line.sysId = Trim_string(line.sysId);
      *bytes = cursor;
      if (outLine)
      {
        *outLine = line;
      }
    }
  }
  return success;
}

void AddLineToTable(arch* arch, htable* syscallTable, syscall_number_line* line)
{
  htable_slot* slot = Get_htable(syscallTable, line->sysId);
  if (slot)
  {
    int* value = &slot->value[arch->archId];
    if (*value == -1)
    {
      // the x86_64 file has a section at the end that lists
      // legacy number for some syscalls, we don't want them
      // so we only take the first number for a given syscall
      *value = line->sysNr;
    }
  }
  else
  {
    slot = Set_htable(syscallTable, line->sysId);
    for (size_t i = 0; i < SIZE_arch_id; ++i)
    {
      slot->value[i] = -1;
    }
    slot->value[arch->archId] = line->sysNr;
  }
}

void LoadSyscallNumbers(arch* arch, htable* syscallTable)
{
  arch->fileBytes = Read_file(arch->inPath);
  assert(arch->fileBytes);

  syscall_number_line line;
  char* cursor = arch->fileBytes;

  while (true)
  {
    if (Read_syscall_number_line(&cursor, &line, arch->archId))
    {
      line.sysNr -= arch->sysNrOffset;
      // printf("%d %.*s %.*s\n", line.sysNr, (int)line.callingConvention.size, line.callingConvention.bytes, (int)line.sysId.size, line.sysId.bytes);
      AddLineToTable(arch, syscallTable, &line);
    }
    else
    {
      if (!ReadUntil(&cursor, "\n", 0))
      {
        break;
      }
    }
  }

  if (arch->archId == ARM_32_arch_id)
  {
    // adding private arm 32 syscalls not defined in the .tbl file
    line = (syscall_number_line){.sysNr = 0x0f0002, .callingConvention = {0}, .sysId = substring("cacheflush") };
    AddLineToTable(arch, syscallTable, &line);

    line = (syscall_number_line){.sysNr = 0x0f0005, .callingConvention = {0}, .sysId = substring("set_tls") };
    AddLineToTable(arch, syscallTable, &line);

    line = (syscall_number_line){.sysNr = 0x0f0006, .callingConvention = {0}, .sysId = substring("get_tls") };
    AddLineToTable(arch, syscallTable, &line);

    // also adding gethostname, it has no number on the 6 arch handled for now,
    // but it should have a wrapper, and also be in the table for consistency
    line = (syscall_number_line){.sysNr = -1, .callingConvention = {0}, .sysId = substring("gethostname") };
    AddLineToTable(arch, syscallTable, &line);
  }

  // printf("\n");
}
void FillKnownSyscallsWithPrototypesButNoNumber(htable* table)
{
  Set_htable(table, substring("newfstat"));
  Set_htable(table, substring("sync_file_range2"));
  Set_htable(table, substring("timerfd_settime32"));
  Set_htable(table, substring("utimensat_time32"));
  Set_htable(table, substring("nanosleep_time32"));
  Set_htable(table, substring("timer_settime32"));
  Set_htable(table, substring("clock_gettime32"));
  Set_htable(table, substring("clock_nanosleep_time32"));
  Set_htable(table, substring("mq_timedreceive_time32"));
  Set_htable(table, substring("old_shmctl"));
  Set_htable(table, substring("spu_run"));
  Set_htable(table, substring("newlstat"));
  Set_htable(table, substring("time32"));
  Set_htable(table, substring("futimesat_time32"));
  Set_htable(table, substring("utimes_time32"));
  Set_htable(table, substring("oldumount"));
  Set_htable(table, substring("chown16"));
  Set_htable(table, substring("fchown16"));
  Set_htable(table, substring("setgid16"));
  Set_htable(table, substring("setuid16"));
  Set_htable(table, substring("getresuid16"));
  Set_htable(table, substring("getresgid16"));
  Set_htable(table, substring("setfsgid16"));
  Set_htable(table, substring("setgroups16"));
  Set_htable(table, substring("geteuid16"));
  Set_htable(table, substring("getegid16"));
  Set_htable(table, substring("old_select"));
  Set_htable(table, substring("old_readdir"));
  Set_htable(table, substring("old_getrlimit"));
  Set_htable(table, substring("mmap_pgoff"));
  Set_htable(table, substring("ni_syscall"));
  Set_htable(table, substring("io_getevents_time32"));
  Set_htable(table, substring("io_pgetevents_time32"));
  Set_htable(table, substring("pselect6_time32"));
  Set_htable(table, substring("ppoll_time32"));
  Set_htable(table, substring("timerfd_gettime32"));
  Set_htable(table, substring("futex_time32"));
  Set_htable(table, substring("timer_gettime32"));
  Set_htable(table, substring("clock_settime32"));
  Set_htable(table, substring("clock_getres_time32"));
  Set_htable(table, substring("sched_rr_get_interval_time32"));
  Set_htable(table, substring("rt_sigtimedwait_time32"));
  Set_htable(table, substring("newuname"));
  Set_htable(table, substring("adjtimex_time32"));
  Set_htable(table, substring("mq_timedsend_time32"));
  Set_htable(table, substring("old_msgctl"));
  Set_htable(table, substring("old_semctl"));
  Set_htable(table, substring("semtimedop_time32"));
  Set_htable(table, substring("recvmmsg_time32"));
  Set_htable(table, substring("clock_adjtime32"));
  Set_htable(table, substring("spu_create"));
  Set_htable(table, substring("newstat"));
  Set_htable(table, substring("utime32"));
  Set_htable(table, substring("stime32"));
  Set_htable(table, substring("lchown16"));
  Set_htable(table, substring("setregid16"));
  Set_htable(table, substring("setreuid16"));
  Set_htable(table, substring("setresuid16"));
  Set_htable(table, substring("setresgid16"));
  Set_htable(table, substring("setfsuid16"));
  Set_htable(table, substring("getgroups16"));
  Set_htable(table, substring("getuid16"));
  Set_htable(table, substring("getgid16"));
  Set_htable(table, substring("old_mmap"));
  Set_htable(table, substring("ni_posix_timers"));
}

char* LoadSyscallPrototypes(htable* syscallTable, char* inPath)
{
  char* bytes = Read_file(inPath);
  assert(bytes);

  htable knownSyscallsWithPrototypesButNoNumber = {0};
  FillKnownSyscallsWithPrototypesButNoNumber(&knownSyscallsWithPrototypesButNoNumber);

  htable knownSyscallsWithMultiplePrototypes = {0};
  Set_htable(&knownSyscallsWithMultiplePrototypes, substring("clone"));
  Set_htable(&knownSyscallsWithMultiplePrototypes, substring("fanotify_mark"));
  Set_htable(&knownSyscallsWithMultiplePrototypes, substring("sigsuspend"));

  char* cursor = bytes;
  substring asmlinkage = {};

  int prototypeCount = 0;
  int prototypeCountWithNumber = 0;
  while (ReadUntilOneOf(&cursor, " \t\n", &asmlinkage))
  {
    // asmlinkage long sys_getresgid16(old_gid_t __user *rgid,
    // 				old_gid_t __user *egid, old_gid_t __user *sgid);
    if (Eq_string(asmlinkage, substring("asmlinkage")))
    {
      substring key = {};
      bool ok = ReadUntil(&cursor, "sys_", 0);
      ok = ok && ReadUntilOneOf(&cursor, "( \t\n", &key);
      ok = ok && ReadUntil(&cursor, ";\n", 0);
      if (ok)
      {
        ++prototypeCount;

        substring prototype = {};
        prototype.bytes = asmlinkage.bytes;
        prototype.size = cursor - prototype.bytes;

        htable_slot* slot = Get_htable(syscallTable, key);
        if (slot)
        {
          ++prototypeCountWithNumber;
          if (slot->prototype.size > 0 && !Get_htable(&knownSyscallsWithMultiplePrototypes, key))
          {
            fprintf(stderr, "(LoadSyscallPrototypes) WARNING: replacing prototype for syscall %.*s: %.*s -> %.*s\n", (int)key.size, key.bytes, (int)slot->prototype.size, slot->prototype.bytes, (int)prototype.size, prototype.bytes);
          }
          slot->prototype = prototype;
        }
        else
        {
          if (!Get_htable(&knownSyscallsWithPrototypesButNoNumber, key))
          {
            fprintf(stderr, "(LoadSyscallPrototypes) WARNING: no syscall number for prototype: %.*s\n", (int)prototype.size, prototype.bytes);
          }
        }
      }
      else
      {
        substring line = {};
        if (cursor[-1] != '\n')
        {
          ReadUntil(&cursor, "\n", &line);
        }
        fprintf(stderr, "(LoadSyscallPrototypes) ERROR: failed to read a line starting with asmlinkage: asmlinkage %.*s\n", (int)line.size, line.bytes);
      }
    }
    else
    {
      if (cursor[-1] != '\n')
      {
        ReadUntil(&cursor, "\n", 0);
      }
    }
  }

  fprintf(stderr, "(LoadSyscallPrototypes) INFO: retrieved %d prototypes from the linux file, %d of which have a syscall number,\n", prototypeCount, prototypeCountWithNumber);

  // Make exit's prototype noreturn
  Get_htable(syscallTable, substring("exit"))->prototype = substring("asmlinkage __attribute__((noreturn)) void sys_exit(int error_code);\n");
  Get_htable(syscallTable, substring("exit_group"))->prototype = substring("asmlinkage __attribute__((noreturn)) void sys_exit_group(int error_code);\n");

  // Manually specifying prototypes that appear multiple times (#ifdef) in the linux file
  Get_htable(syscallTable, substring("clone"))->prototype = substring("asmlinkage long sys_clone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls);\n");
  Get_htable(syscallTable, substring("fanotify_mark"))->prototype = substring("asmlinkage long sys_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname);\n");
  Get_htable(syscallTable, substring("sigsuspend"))->prototype = substring("asmlinkage long sys_sigsuspend(old_sigset_t mask);\n");

  // Override architecture dependent sizes
  Get_htable(syscallTable, substring("sched_rr_get_interval"))->prototype = substring("asmlinkage long sys_sched_rr_get_interval(int pid, __kernel_old_timespec *interval);\n");
  Get_htable(syscallTable, substring("ppoll"))->prototype = substring("long sys_ppoll(pollfd *, unsigned int, __kernel_old_timespec *, const sigset_t *, unsigned long);\n");
  Get_htable(syscallTable, substring("utimensat"))->prototype = substring("long sys_utimensat(int dfd, const char *filename, __kernel_old_timespec *utimes, int flags);\n");
  Get_htable(syscallTable, substring("rt_sigtimedwait"))->prototype = substring("long sys_rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const __kernel_old_timespec *uts, unsigned long sigsetsize);\n");
  Get_htable(syscallTable, substring("semtimedop"))->prototype = substring("long sys_semtimedop(int semid, sembuf *sops, unsigned nsops, const __kernel_old_timespec *timeout);\n");
  Get_htable(syscallTable, substring("mq_timedsend"))->prototype = substring("long sys_mq_timedsend(mqd_t mqdes, const char *msg_ptr, unsigned long msg_len, unsigned int msg_prio, const __kernel_old_timespec *abs_timeout);\n");
  Get_htable(syscallTable, substring("mq_timedreceive"))->prototype = substring("long sys_mq_timedreceive(mqd_t mqdes, char *msg_ptr, unsigned long msg_len, unsigned int *msg_prio, const __kernel_old_timespec *abs_timeout);\n");
  Get_htable(syscallTable, substring("futex"))->prototype = substring("long sys_futex(u32 *uaddr, int op, u32 val, const __kernel_old_timespec *utime, u32 *uaddr2, u32 val3);\n");
  Get_htable(syscallTable, substring("recvmmsg"))->prototype = substring("long sys_recvmmsg(int fd, mmsghdr *msg, unsigned int vlen, unsigned flags, __kernel_old_timespec *timeout);\n");
  Get_htable(syscallTable, substring("io_pgetevents"))->prototype = substring("long sys_io_pgetevents(aio_context_t ctx_id, long min_nr, long nr, io_event *events, __kernel_old_timespec *timeout, const __aio_sigset *sig);\n");
  Get_htable(syscallTable, substring("clock_gettime"))->prototype = substring("long sys_clock_gettime(clockid_t which_clock, __kernel_old_timespec *tp);\n");
  Get_htable(syscallTable, substring("clock_getres"))->prototype = substring("long sys_clock_getres(clockid_t which_clock, __kernel_old_timespec *tp);\n");
  Get_htable(syscallTable, substring("clock_settime"))->prototype = substring("long sys_clock_settime(clockid_t which_clock, const __kernel_old_timespec *tp);\n");
  Get_htable(syscallTable, substring("clock_nanosleep"))->prototype = substring("long sys_clock_nanosleep(clockid_t which_clock, int flags, const __kernel_old_timespec *rqtp, __kernel_old_timespec *rmtp);\n");

  // Manually add arg names for prototypes that don't have them
  Get_htable(syscallTable, substring("pselect6"))->prototype = substring("long sys_pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp, __kernel_old_timespec *tsp, void *sig);\n");
  Get_htable(syscallTable, substring("sigaction"))->prototype = substring("asmlinkage long sys_sigaction(int sig, const struct old_sigaction __user *act, struct old_sigaction __user *oact);\n");
  Get_htable(syscallTable, substring("rt_sigaction"))->prototype = substring("asmlinkage long sys_rt_sigaction(int sig, const struct sigaction __user *act, struct sigaction __user *oact, size_t sigsetsize);\n");
  Get_htable(syscallTable, substring("socket"))->prototype = substring("asmlinkage long sys_socket(int family, int type, int protocol);\n");
  Get_htable(syscallTable, substring("socketpair"))->prototype = substring("asmlinkage long sys_socketpair(int family, int type, int protocol, int __user *usockvec);\n");
  Get_htable(syscallTable, substring("bind"))->prototype = substring("asmlinkage long sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen);\n");
  Get_htable(syscallTable, substring("listen"))->prototype = substring("asmlinkage long sys_listen(int fd, int backlog);\n");
  Get_htable(syscallTable, substring("accept"))->prototype = substring("asmlinkage long sys_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen);\n");
  Get_htable(syscallTable, substring("accept4"))->prototype = substring("asmlinkage long sys_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags);\n");
  Get_htable(syscallTable, substring("connect"))->prototype = substring("asmlinkage long sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen);\n");
  Get_htable(syscallTable, substring("shutdown"))->prototype = substring("asmlinkage long sys_shutdown(int fd, int how);\n");
  Get_htable(syscallTable, substring("send"))->prototype = substring("asmlinkage long sys_send(int fd, void __user *buff, size_t len, unsigned int flags);\n");
  Get_htable(syscallTable, substring("sendto"))->prototype = substring("asmlinkage long sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len);\n");
  Get_htable(syscallTable, substring("recv"))->prototype = substring("asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size, unsigned int flags);\n");
  Get_htable(syscallTable, substring("recvfrom"))->prototype = substring("asmlinkage long sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);\n");
  Get_htable(syscallTable, substring("getsockname"))->prototype = substring("asmlinkage long sys_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);\n");
  Get_htable(syscallTable, substring("getpeername"))->prototype = substring("asmlinkage long sys_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);\n");
  Get_htable(syscallTable, substring("io_submit"))->prototype = substring("asmlinkage long sys_io_submit(aio_context_t ctx_id, long nr, struct iocb __user * __user *iocbpp);\n");

  // Additional prototypes missing from the linux file, these might be unreliable
  Get_htable(syscallTable, substring("arch_prctl"))->prototype = substring("asmlinkage long sys_arch_prctl(int option, unsigned long addr);\n");
  Get_htable(syscallTable, substring("modify_ldt"))->prototype = substring("asmlinkage long sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount);\n");
  Get_htable(syscallTable, substring("set_thread_area"))->prototype = substring("asmlinkage long sys_set_thread_area(struct user_desc __user *u_info);\n");
  Get_htable(syscallTable, substring("get_thread_area"))->prototype = substring("asmlinkage long sys_get_thread_area(struct user_desc __user *u_info);\n");
  Get_htable(syscallTable, substring("mmap"))->prototype = substring("asmlinkage long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);\n");
  Get_htable(syscallTable, substring("mmap2"))->prototype = substring("asmlinkage long sys_mmap2(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);\n");
  Get_htable(syscallTable, substring("arm_fadvise64_64"))->prototype = substring("asmlinkage long sys_arm_fadvise64_64(int fd, int advice, loff_t offset, loff_t len);\n");
  Get_htable(syscallTable, substring("rt_sigtimedwait_time64"))->prototype = substring("asmlinkage long sys_rt_sigtimedwait_time64(compat_sigset_t __user *uthese, struct compat_siginfo __user *uinfo, struct __kernel_timespec __user *uts, compat_size_t sigsetsize);\n");
  Get_htable(syscallTable, substring("sigreturn"))->prototype = substring("asmlinkage long sys_sigreturn(struct pt_regs *regs);\n");
  Get_htable(syscallTable, substring("rt_sigreturn"))->prototype = substring("asmlinkage long sys_rt_sigreturn(struct pt_regs *regs);\n");
  Get_htable(syscallTable, substring("iopl"))->prototype = substring("asmlinkage long sys_iopl(unsigned int level);\n");
  Get_htable(syscallTable, substring("riscv_flush_icache"))->prototype = substring("asmlinkage long sys_riscv_flush_icache(uintptr_t start, uintptr_t end, uintptr_t flags);\n");
  Get_htable(syscallTable, substring("riscv_hwprobe"))->prototype = substring("asmlinkage long sys_riscv_hwprobe(struct riscv_hwprobe __user *pairs, size_t pair_count, size_t cpu_count, unsigned long __user *cpumask, unsigned int flags);\n");
  Get_htable(syscallTable, substring("vm86"))->prototype = substring("asmlinkage long sys_vm86(unsigned long cmd, unsigned long arg);\n");
  Get_htable(syscallTable, substring("vm86old"))->prototype = substring("asmlinkage long sys_vm86old(struct vm86_struct __user *user_vm86);\n");
  Get_htable(syscallTable, substring("set_tls"))->prototype = substring("asmlinkage long sys_set_tls(unsigned long val);\n");
  Get_htable(syscallTable, substring("get_tls"))->prototype = substring("asmlinkage long sys_get_tls(void);\n");
  Get_htable(syscallTable, substring("sched_rr_get_interval_time64"))->prototype = substring("asmlinkage long sys_sched_rr_get_interval_time64(pid_t pid, struct __kernel_timespec __user *interval);\n");
  Get_htable(syscallTable, substring("_llseek"))->prototype = substring("asmlinkage long sys__llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);\n");
  Get_htable(syscallTable, substring("arm_sync_file_range"))->prototype = substring("asmlinkage long sys_arm_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags);\n");
  Get_htable(syscallTable, substring("_newselect"))->prototype = substring("asmlinkage long sys__newselect(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_old_timeval __user *tvp);\n");
  Get_htable(syscallTable, substring("pselect6_time64"))->prototype = substring("asmlinkage long sys_pselect6_time64(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct __kernel_timespec __user *tsp, void __user *sig);\n");
  Get_htable(syscallTable, substring("ppoll_time64"))->prototype = substring("asmlinkage long sys_ppoll_time64(struct pollfd __user *ufds, unsigned int nfds, struct __kernel_timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize);\n");
  Get_htable(syscallTable, substring("epoll_ctl_old"))->prototype = substring("asmlinkage long sys_epoll_ctl_old(int epfd, int op, int fd, struct epoll_event __user *event);\n");
  Get_htable(syscallTable, substring("epoll_wait_old"))->prototype = substring("asmlinkage long sys_epoll_wait_old(int epfd, struct epoll_event __user *events, int maxevents, int timeout);\n");
  Get_htable(syscallTable, substring("oldstat"))->prototype = substring("asmlinkage long sys_oldstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);\n");
  Get_htable(syscallTable, substring("oldfstat"))->prototype = substring("asmlinkage long sys_oldfstat(unsigned int fd, struct __old_kernel_stat __user *statbuf);\n");
  Get_htable(syscallTable, substring("oldlstat"))->prototype = substring("asmlinkage long sys_oldlstat(const char __user *filename, struct __old_kernel_stat __user *statbuf);\n");
  Get_htable(syscallTable, substring("chown32"))->prototype = substring("asmlinkage long sys_chown32(const char __user *filename, uid_t user, gid_t group);\n");
  Get_htable(syscallTable, substring("fchown32"))->prototype = substring("asmlinkage long sys_fchown32(unsigned int fd, uid_t user, gid_t group);\n");
  Get_htable(syscallTable, substring("lchown32"))->prototype = substring("asmlinkage long sys_lchown32(const char __user *filename, uid_t user, gid_t group);\n");
  Get_htable(syscallTable, substring("utimensat_time64"))->prototype = substring("asmlinkage long sys_utimensat_time64(int dfd, const char __user *filename, struct __kernel_timespec __user *t, int flags);\n");
  Get_htable(syscallTable, substring("readdir"))->prototype = substring("asmlinkage long sys_readdir(unsigned int fd, struct old_linux_dirent __user *dirent, unsigned int count);\n");
  Get_htable(syscallTable, substring("umount2"))->prototype = substring("asmlinkage long sys_umount2(char __user *name, int flags);\n");
  Get_htable(syscallTable, substring("semtimedop_time64"))->prototype = substring("asmlinkage long sys_semtimedop_time64(int semid, struct sembuf __user *tsops, unsigned int nsops, const struct __kernel_timespec __user *timeout);\n");
  Get_htable(syscallTable, substring("mq_timedsend_time64"))->prototype = substring("asmlinkage long sys_mq_timedsend_time64(mqd_t mqdes, const char __user *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const struct __kernel_timespec __user *u_abs_timeout);\n");
  Get_htable(syscallTable, substring("mq_timedreceive_time64"))->prototype = substring("asmlinkage long sys_mq_timedreceive_time64(mqd_t mqdes, char __user *u_msg_ptr, size_t msg_len, unsigned int __user *u_msg_prio, const struct __kernel_timespec __user *u_abs_timeout);\n");
  Get_htable(syscallTable, substring("futex_time64"))->prototype = substring("asmlinkage long sys_futex_time64(u32 __user *uaddr, int op, u32 val, const struct __kernel_timespec __user *utime, u32 __user *uaddr2, u32 val3);\n");
  Get_htable(syscallTable, substring("recvmmsg_time64"))->prototype = substring("asmlinkage long sys_recvmmsg_time64(int fd, struct mmsghdr __user *mmsg, unsigned int vlen, unsigned int flags, struct __kernel_timespec __user *timeout);\n");
  Get_htable(syscallTable, substring("io_pgetevents_time64"))->prototype = substring("asmlinkage long sys_io_pgetevents_time64(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct __kernel_timespec __user *timeout, const struct __aio_sigset __user *sig);\n");
  Get_htable(syscallTable, substring("clock_gettime64"))->prototype = substring("asmlinkage long sys_clock_gettime64(clockid_t which_clock, struct __kernel_timespec __user *tp);\n");
  Get_htable(syscallTable, substring("clock_getres_time64"))->prototype = substring("asmlinkage long sys_clock_getres_time64(clockid_t which_clock, struct __kernel_timespec __user *tp);\n");
  Get_htable(syscallTable, substring("clock_settime64"))->prototype = substring("asmlinkage long sys_clock_settime64(clockid_t which_clock, const struct __kernel_timespec __user *tp);\n");
  Get_htable(syscallTable, substring("clock_adjtime64"))->prototype = substring("asmlinkage long sys_clock_adjtime64(clockid_t which_clock, struct __kernel_timex __user *tx);\n");
  Get_htable(syscallTable, substring("clock_nanosleep_time64"))->prototype = substring("asmlinkage long sys_clock_nanosleep_time64(clockid_t which_clock, int flags, const struct __kernel_timespec __user *rqtp, struct __kernel_timespec __user *rmtp);\n");
  Get_htable(syscallTable, substring("timer_settime64"))->prototype = substring("asmlinkage long sys_timer_settime64(timer_t timerid, int flags, const struct __kernel_timespec __user *new_setting, struct __kernel_timespec __user *old_setting);\n");
  Get_htable(syscallTable, substring("timer_gettime64"))->prototype = substring("asmlinkage long sys_timer_gettime64(timer_t timerid, struct __kernel_timespec __user *setting);\n");
  Get_htable(syscallTable, substring("timerfd_settime64"))->prototype = substring("asmlinkage long sys_timerfd_settime64(int ufd, int flags, const struct __kernel_timespec __user *utmr, struct __kernel_timespec __user *otmr);\n");
  Get_htable(syscallTable, substring("timerfd_gettime64"))->prototype = substring("asmlinkage long sys_timerfd_gettime64(int ufd, struct __kernel_timespec __user *otmr);\n");
  Get_htable(syscallTable, substring("getuid32"))->prototype = substring("asmlinkage long sys_getuid32(void);\n");
  Get_htable(syscallTable, substring("geteuid32"))->prototype = substring("asmlinkage long sys_geteuid32(void);\n");
  Get_htable(syscallTable, substring("setuid32"))->prototype = substring("asmlinkage long sys_setuid32(uid_t uid);\n");
  Get_htable(syscallTable, substring("setreuid32"))->prototype = substring("asmlinkage long sys_setreuid32(uid_t ruid, uid_t euid);\n");
  Get_htable(syscallTable, substring("setresuid32"))->prototype = substring("asmlinkage long sys_setresuid32(uid_t ruid, uid_t euid, uid_t suid);\n");
  Get_htable(syscallTable, substring("getresuid32"))->prototype = substring("asmlinkage long sys_getresuid32(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);\n");
  Get_htable(syscallTable, substring("setfsuid32"))->prototype = substring("asmlinkage long sys_setfsuid32(uid_t uid);\n");
  Get_htable(syscallTable, substring("getgid32"))->prototype = substring("asmlinkage long sys_getgid32(void);\n");
  Get_htable(syscallTable, substring("getegid32"))->prototype = substring("asmlinkage long sys_getegid32(void);\n");
  Get_htable(syscallTable, substring("setgid32"))->prototype = substring("asmlinkage long sys_setgid32(gid_t gid);\n");
  Get_htable(syscallTable, substring("setregid32"))->prototype = substring("asmlinkage long sys_setregid32(gid_t rgid, gid_t egid);\n");
  Get_htable(syscallTable, substring("setresgid32"))->prototype = substring("asmlinkage long sys_setresgid32(gid_t rgid, gid_t egid, gid_t sgid);\n");
  Get_htable(syscallTable, substring("getresgid32"))->prototype = substring("asmlinkage long sys_getresgid32(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);\n");
  Get_htable(syscallTable, substring("setfsgid32"))->prototype = substring("asmlinkage long sys_setfsgid32(gid_t gid);\n");
  Get_htable(syscallTable, substring("getgroups32"))->prototype = substring("asmlinkage long sys_getgroups32(int gidsetsize, gid_t __user *grouplist);\n");
  Get_htable(syscallTable, substring("setgroups32"))->prototype = substring("asmlinkage long sys_setgroups32(int gidsetsize, gid_t __user *grouplist);\n");
  Get_htable(syscallTable, substring("security"))->prototype = substring("asmlinkage long sys_security(void);\n");
  Get_htable(syscallTable, substring("ugetrlimit"))->prototype = substring("asmlinkage long sys_ugetrlimit(unsigned int resource, struct rlimit __user *rlim);\n");
  Get_htable(syscallTable, substring("ulimit"))->prototype = substring("asmlinkage long sys_ulimit(int cmd, long newval);\n");
  Get_htable(syscallTable, substring("oldolduname"))->prototype = substring("asmlinkage long sys_oldolduname(struct oldold_utsname __user *name);\n");
  Get_htable(syscallTable, substring("create_module"))->prototype = substring("asmlinkage long sys_create_module(const char __user *name, size_t size);\n");
  Get_htable(syscallTable, substring("query_module"))->prototype = substring("asmlinkage long sys_query_module(const char __user *name, int which, void __user *buf, size_t bufsize, size_t __user *ret);\n");
  Get_htable(syscallTable, substring("get_kernel_syms"))->prototype = substring("asmlinkage long sys_get_kernel_syms(struct kernel_sym __user *table);\n");
  Get_htable(syscallTable, substring("cacheflush"))->prototype = substring("asmlinkage long sys_cacheflush(unsigned long start, unsigned long end, int flags);\n");
  Get_htable(syscallTable, substring("mpx"))->prototype = substring("asmlinkage long sys_mpx(void);\n");
  Get_htable(syscallTable, substring("lookup_dcookie"))->prototype = substring("asmlinkage long sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len);\n");
  Get_htable(syscallTable, substring("_sysctl"))->prototype = substring("asmlinkage long sys__sysctl(struct __sysctl_args __user *args);\n");
  Get_htable(syscallTable, substring("profil"))->prototype = substring("asmlinkage long sys_profil(unsigned short __user *sample_buffer, size_t size, unsigned long offset, unsigned int scale);\n");
  Get_htable(syscallTable, substring("prof"))->prototype = substring("asmlinkage long sys_prof(void);\n");
  Get_htable(syscallTable, substring("afs_syscall"))->prototype = substring("asmlinkage long sys_afs_syscall(void);\n");
  Get_htable(syscallTable, substring("break"))->prototype = substring("asmlinkage long sys_break(void);\n");
  Get_htable(syscallTable, substring("ftime"))->prototype = substring("asmlinkage long sys_ftime(void);\n");
  Get_htable(syscallTable, substring("gtty"))->prototype = substring("asmlinkage long sys_gtty(void);\n");
  Get_htable(syscallTable, substring("idle"))->prototype = substring("asmlinkage long sys_idle(void);\n");
  Get_htable(syscallTable, substring("lock"))->prototype = substring("asmlinkage long sys_lock(void);\n");
  Get_htable(syscallTable, substring("nfsservctl"))->prototype = substring("asmlinkage long sys_nfsservctl(int cmd, struct nfsctl_arg __user *arg, union nfsctl_res __user *res);\n");
  Get_htable(syscallTable, substring("getpmsg"))->prototype = substring("asmlinkage long sys_getpmsg(int fd, struct strbuf __user *ctlptr, struct strbuf __user *dataptr, int __user *bandp, int __user *flagsp);\n");
  Get_htable(syscallTable, substring("putpmsg"))->prototype = substring("asmlinkage long sys_putpmsg(int fd, struct strbuf __user *ctlptr, struct strbuf __user *dataptr, int band, int flags);\n");
  Get_htable(syscallTable, substring("stty"))->prototype = substring("asmlinkage long sys_stty(void);\n");
  Get_htable(syscallTable, substring("tuxcall"))->prototype = substring("asmlinkage long sys_tuxcall(void);\n");
  Get_htable(syscallTable, substring("vserver"))->prototype = substring("asmlinkage long sys_vserver(void);\n");
  Get_htable(syscallTable, substring("bdflush"))->prototype = substring("asmlinkage long sys_bdflush(int func, long data);\n");

  Free_htable(&knownSyscallsWithPrototypesButNoNumber);
  Free_htable(&knownSyscallsWithMultiplePrototypes);
  return bytes;
}

void PrintSyscallNumber(FILE* file, int archId, substring sysId, int sysNr)
{
  if (sysNr == -1)
  {
    fprintf(file, "    void");
  }
  else if (archId == ARM_32_arch_id &&
     (Eq_string(sysId, substring("cacheflush"))
   || Eq_string(sysId, substring("set_tls"))
   || Eq_string(sysId, substring("get_tls"))))
  {
    fprintf(file, "%#08x", sysNr);
  }
  else
  {
    fprintf(file, "% 8d", sysNr);
  }
}

void PrintSyscallNumbersSorted(arch* arch, htable* syscallTable)
{
  table sortedSyscalls = {0};
  for (size_t i = 0; i < syscallTable->capacity; ++i)
  {
    htable_slot* slot = &syscallTable->slots[i];
    if (slot->state == OCCUPIED_htable_slot_state)
    {
      *Push_table(&sortedSyscalls) = slot;
    }
  }

  assert(syscallTable->size == sortedSyscalls.size);

  Quicksort_table(&sortedSyscalls);

  FILE* file = fopen(arch->outPath, "w");
  assert(file);

  for (size_t i = 0; i < sortedSyscalls.size; ++i)
  {
    htable_slot* slot = sortedSyscalls.items[i];
    int sysNr = slot->value[arch->archId];

    if (sysNr != -1)
    {
      fprintf(file, "#define __NR_%.*s ", (int)slot->key.size, slot->key.bytes);
      if (arch->archId == ARM_32_arch_id &&
         (Eq_string(slot->key, substring("cacheflush"))
       || Eq_string(slot->key, substring("set_tls"))
       || Eq_string(slot->key, substring("get_tls"))))
      {
        fprintf(file, "%#08x", sysNr);
      }
      else
      {
        fprintf(file, "%d", sysNr);
      }
      fprintf(file, "\n");
    }
  }

  Free_table(&sortedSyscalls);
  assert(fwrite("\n", 1, 1, file) == 1);
  fclose(file);
}

struct table_dimensions
{
  int maxSysIdSize;
  int tableStart;
  int textStart;
  int defineStart;
  int archStart;
  int tableEnd;
  int charCountInLine;
} table_dimensions;

table_dimensions Get_table_dimensions(int maxSysIdSize)
{
  table_dimensions dimensions = {0};
  dimensions.maxSysIdSize = maxSysIdSize;
  dimensions.tableStart = strlen("/*");
  dimensions.textStart = dimensions.tableStart + strlen("| ");
  dimensions.defineStart = dimensions.tableStart + strlen("|*/ ");
  dimensions.archStart = dimensions.defineStart + strlen("#define NR_") + dimensions.maxSysIdSize + strlen("_linux ") + strlen("BY_ARCH_linux");
  dimensions.tableEnd = dimensions.archStart + SIZE_arch_id * 10 + strlen(") /*");
  dimensions.charCountInLine = dimensions.tableEnd + 1;
  return dimensions;
}

bool IsArchSeparator(table_dimensions* dimensions, int i)
{
  bool out = false;
  for (enum arch_id archId = 0; archId < SIZE_arch_id; ++archId)
  {
    int archStart = dimensions->archStart + 10*archId;
    if (i == archStart)
    {
      out = true;
      break;
    }
  }
  return out;
}

void PrintN(FILE* file, char* s, int n)
{
  for (int i = 0; i < n; ++i)
  {
    fprintf(file, "%s", s);
  }
}

void PrintAndRemoveSyscall(FILE* file, htable* syscallTable, substring key, int maxSysIdSize)
{
  htable_slot* slot = Get_htable(syscallTable, key);
  if (slot)
  {
    fprintf(file, "/*║*/ #define NR_");
    for (size_t j = 0; j < key.size; ++j)
    {
      // fprintf(file, "%c", Capitalize(key.bytes[j]));
      fprintf(file, "%c", key.bytes[j]);
    }
    fprintf(file, "_linux ");
    PrintN(file, " ", maxSysIdSize - key.size);
    fprintf(file, "BY_ARCH_linux( ");
    for (int archId = 0; archId < SIZE_arch_id - 1; ++archId)
    {
      PrintSyscallNumber(file, archId, key, slot->value[archId]);
      fprintf(file, ", ");
    }
    if (SIZE_arch_id)
    {
      int archId = SIZE_arch_id - 1;
      PrintSyscallNumber(file, archId, key, slot->value[archId]);
    }
    fprintf(file, ") /*║*/\n");
    Remove_htable_slot(syscallTable, slot);
  }
  else
  {
    fprintf(file, "#error syscall %.*s is not in the syscall table\n", (int)key.size, key.bytes);
  }
}

int CenterOffset(char* s, int n)
{
  int slen = strlen(s);
  assert(n > slen);
  return (n - slen)/2;
}

void PrintTableTopLine(FILE* file, table_dimensions* dimensions)
{
  fprintf(file, "/*╔");
  PrintN(file, "═", dimensions->charCountInLine - 4);
  fprintf(file, "╗*/\n");
}

void PrintTableBottomLine(FILE* file, table_dimensions* dimensions)
{
  fprintf(file, "/*╚");
  PrintN(file, "═", dimensions->charCountInLine - 4);
  fprintf(file, "╝*/\n");
}

void PrintTableTextLine(FILE* file, char* s, table_dimensions* dimensions)
{
  fprintf(file, "/*║ %s", s);
  int n = dimensions->charCountInLine - strlen("/*| ") - strlen(s) - strlen("|");
  assert(n > 0);
  PrintN(file, " ", n);
  fprintf(file, "║*/\n");
}

void PrintTableTextLineCentered(FILE* file, char* s, table_dimensions* dimensions)
{
  if (s)
  {
    fprintf(file, "/*║");
    int n = dimensions->tableEnd - dimensions->tableStart - 1;
    int offset = CenterOffset(s, n);
    PrintN(file, " ", offset);
    fprintf(file, "%s", s);
    PrintN(file, " ", n - offset - strlen(s));
    fprintf(file, "║*/\n");
  }
}

void PrintTableSeparatorLineEx(FILE* file, char* archSeparator, char* archSeparatorFirst, char* separator, table_dimensions* dimensions)
{
  fprintf(file, "/*");

  if (streq(separator, "─"))
  {
    fprintf(file, "╟");
  }
  else
  {
    fprintf(file, "╠");
  }

  bool isFirstArchSeparator = true;
  for (int i = dimensions->tableStart + 1; i < dimensions->tableEnd; ++i)
  {
    if (IsArchSeparator(dimensions, i))
    {
      if (isFirstArchSeparator)
      {
        fprintf(file, "%s", archSeparatorFirst);
        isFirstArchSeparator = false;
      }
      else
      {
        fprintf(file, "%s", archSeparator);
      }
    }
    else
    {
      fprintf(file, "%s", separator);
    }
  }

  if (streq(separator, "─"))
  {
    fprintf(file, "╢");
  }
  else
  {
    fprintf(file, "╣");
  }
  fprintf(file, "*/\n");
}

void PrintTableSeparatorLine(FILE* file, char* archSeparator, table_dimensions* dimensions)
{
  PrintTableSeparatorLineEx(file, archSeparator, archSeparator, "═", dimensions);
}

void PrintTableArchitectureLine(FILE* file, table_dimensions* dimensions)
{
  char* label = "Syscall Name";
  int colSize = dimensions->archStart - dimensions->tableStart - 1;
  fprintf(file, "/*║");
  int offset = CenterOffset(label, colSize);
  PrintN(file, " ", offset);
  fprintf(file, "%s", label);
  PrintN(file, " ", colSize - offset - strlen(label));
  fprintf(file, "║");

  for (int i = 0; i < SIZE_arch_id; ++i)
  {
    enum arch_id archId = i;
    int archColSize = 9 + strlen(") /*")*(i == SIZE_arch_id - 1);
    char* archName = GetArchName(archId);
    int archOffset = CenterOffset(archName, archColSize);
    PrintN(file, " ", archOffset);
    fprintf(file, "%s", archName);
    PrintN(file, " ", archColSize - archOffset - strlen(archName));
    if (i == SIZE_arch_id - 1)
    {
      fprintf(file, "║*/\n");
    }
    else
    {
      fprintf(file, "│");
    }
  }
}

enum table_printer_state
{
  PRINTED_NOTHING_table_printer_state = 0,
  PRINTED_SECTION_table_printer_state,
  PRINTED_SYSCALL_table_printer_state,
};

#define MAX_SESSION_TITLES 64
struct table_printer
{
  FILE* out;
  FILE* wrapperPrototypesFile;
  FILE* wrapperImplementationFile;

  table_dimensions dimensions;
  htable* syscallTable;

  enum table_printer_state state;
  int sectionNumber;
  char subsectionLetter;

  int linesPrintedSinceLastArchSection;

  char* sectionTitles[MAX_SESSION_TITLES];
  int sectionTitlesCount;

  bool disabledWrapper;
  char* customWrapper;
} table_printer;

void PushSectionTitle(table_printer* printer, char* title)
{
  assert(printer->sectionTitlesCount != MAX_SESSION_TITLES);
  printer->sectionTitles[printer->sectionTitlesCount++] = title;
}

void PrintTableSummary(table_printer* printer)
{
  PrintTableTopLine(stderr, &printer->dimensions);
  PrintTableTextLineCentered(stderr, "LINUX SYSCALL TABLE", &printer->dimensions);
  PrintTableSeparatorLine(stderr, "═", &printer->dimensions);
  PrintTableTextLineCentered(stderr, "Section List", &printer->dimensions);
  PrintTableSeparatorLineEx(stderr, "─", "─", "─", &printer->dimensions);

  size_t colCount = 3;
  size_t linesCount = (printer->sectionTitlesCount + colCount - 1) / colCount;
  size_t colSize = (printer->dimensions.charCountInLine - strlen("/*|  |")) / colCount;

  for (size_t i = 0; i < linesCount; ++i)
  {
    char buffer[256] = {0};
    for (size_t col = 0; col < colCount; ++col)
    {
      size_t titleIndex = i + col*linesCount;
      if (titleIndex >= printer->sectionTitlesCount)
      {
        break;
      }
      assert(col*colSize < sizeof(buffer));
      snprintf(buffer + col*colSize, colSize + 1, "%2zu. %-*s", titleIndex + 1, (int)(colSize - 4), printer->sectionTitles[titleIndex]);
    }
    PrintTableTextLine(stderr, buffer, &printer->dimensions);
  }

  PrintTableSeparatorLineEx(stderr, "─", "─", "─", &printer->dimensions);
}

void PrintSection(table_printer* printer, char* title, char* subtitle)
{
  if (printer->state == PRINTED_NOTHING_table_printer_state)
  {
    PrintTableTopLine(printer->out, &printer->dimensions);
  }
  else
  {
    PrintTableSeparatorLine(printer->out, "═", &printer->dimensions);
  }
  ++printer->linesPrintedSinceLastArchSection;

  char buffer[256] = {0};
  snprintf(buffer, sizeof(buffer), "%d. %s", printer->sectionNumber + 1, title);
  PrintTableTextLineCentered(printer->out, buffer, &printer->dimensions);
  ++printer->linesPrintedSinceLastArchSection;

  fprintf(printer->wrapperPrototypesFile, "//\n");
  fprintf(printer->wrapperPrototypesFile, "// %s\n", buffer);
  fprintf(printer->wrapperPrototypesFile, "//\n");

  fprintf(printer->wrapperImplementationFile, "//\n");
  fprintf(printer->wrapperImplementationFile, "// %s\n", buffer);
  fprintf(printer->wrapperImplementationFile, "//\n");

  PushSectionTitle(printer, title);

  if (subtitle)
  {
    PrintTableTextLineCentered(printer->out, subtitle, &printer->dimensions);
    ++printer->linesPrintedSinceLastArchSection;
  }

  if (printer->state == PRINTED_NOTHING_table_printer_state
   || printer->linesPrintedSinceLastArchSection >= 30)
  {
    PrintTableSeparatorLineEx(printer->out, "╤", "╦", "═", &printer->dimensions);
    PrintTableArchitectureLine(printer->out, &printer->dimensions);
    PrintTableSeparatorLineEx(printer->out, "┴", "╨", "─", &printer->dimensions);
    printer->linesPrintedSinceLastArchSection = 0;
  }
  else
  {
    PrintTableSeparatorLine(printer->out, "═", &printer->dimensions);
    ++printer->linesPrintedSinceLastArchSection;
  }
  printer->state = PRINTED_SECTION_table_printer_state;
  printer->subsectionLetter = 'a';
  ++printer->sectionNumber;
}

void PrintSubsection(table_printer* printer, char* title)
{
  assert(printer->state != PRINTED_NOTHING_table_printer_state);
  if (printer->state == PRINTED_SYSCALL_table_printer_state)
  {
    PrintTableSeparatorLineEx(printer->out, "─", "─", "─", &printer->dimensions);
    ++printer->linesPrintedSinceLastArchSection;
  }

  char buffer[256] = {0};
  snprintf(buffer, sizeof(buffer), "%d%c. %s", printer->sectionNumber, printer->subsectionLetter, title);
  PrintTableTextLineCentered(printer->out, buffer, &printer->dimensions);
  ++printer->linesPrintedSinceLastArchSection;

  fprintf(printer->wrapperPrototypesFile, "// %s\n", buffer);
  fprintf(printer->wrapperImplementationFile, "// %s\n", buffer);

  PrintTableSeparatorLineEx(printer->out, "─", "─", "─", &printer->dimensions);
  ++printer->linesPrintedSinceLastArchSection;

  printer->state = PRINTED_SECTION_table_printer_state;
  ++printer->subsectionLetter;

  assert(printer->subsectionLetter <= 'z');
}

void SkipSpaces(char **s)
{
  if (s && *s)
  {
    while (IsSpace(**s))
    {
      *s = *s+1;
    }
  }
}

substring ReplaceLinuxType(substring linuxType)
{
  substring out = linuxType;
  if (Eq_string(linuxType, substring("pid_t")))
  {
    out = substring("int");
  }
  else if (Eq_string(linuxType, substring("size_t")))
  {
    out = substring("unsigned long");
  }
  else if (Eq_string(linuxType, substring("clone_args")))
  {
    out = substring("clone_args_linux");
  }
  else if (Eq_string(linuxType, substring("rusage")))
  {
    out = substring("rusage_linux");
  }
  else if (Eq_string(linuxType, substring("siginfo")))
  {
    out = substring("siginfo_t_linux");
  }
  else if (Eq_string(linuxType, substring("__kernel_old_timespec")))
  {
    out = substring("__kernel_old_timespec_linux");
  }
  else if (Eq_string(linuxType, substring("__kernel_timespec")))
  {
    out = substring("__kernel_timespec_linux");
  }
  else if (Eq_string(linuxType, substring("sched_attr")))
  {
    out = substring("sched_attr_linux");
  }
  else if (Eq_string(linuxType, substring("sched_param")))
  {
    out = substring("sched_param_linux");
  }
  return out;
}

void PrintSyscallLine(table_printer* printer, char* s) {
  assert(printer->state != PRINTED_NOTHING_table_printer_state);

  // syscall wrapper prototype and implementation handling
  substring key = substring(s);
  htable_slot* slot = Get_htable(printer->syscallTable, key);
  if (slot)
  {
    if (slot->prototype.size == 0)
    {
      fprintf(stderr, "ERROR: missing prototype for %.*s\n", (int)key.size, key.bytes);
    }
    else
    {
      if (printer->disabledWrapper)
      {
        fprintf(printer->wrapperPrototypesFile, "// Disabled wrapper: ");
        fprintf(printer->wrapperImplementationFile, "// Disabled wrapper: ");
      }

      substring argNames[6] = {0};
      int argNamesCount = 0;

      char* cursor = slot->prototype.bytes;
      assert(ReadUntil(&cursor, " ", 0));

      substring returnType = {0};
      assert(ReadUntil(&cursor, "sys_", &returnType));

      substring syscallName = {0};
      assert(ReadUntil(&cursor, "(", &syscallName));
      fprintf(printer->wrapperPrototypesFile, "%.*s%.*s_linux(", (int)returnType.size, returnType.bytes, (int)syscallName.size, syscallName.bytes);
      fprintf(printer->wrapperImplementationFile, "%.*s%.*s_linux(", (int)returnType.size, returnType.bytes, (int)syscallName.size, syscallName.bytes);

      substring arg = {0};
      do
      {
        assert(ReadUntilOneOf(&cursor, ",)", &arg));
        char* argCursor = arg.bytes;
        bool sawType = false;
        SkipSpaces(&argCursor);
        char delim = 0;
        do
        {
          substring buf = {0};
          SkipSpaces(&argCursor);
          assert(ReadUntilOneOf(&argCursor, " ,)", &buf));
          delim = argCursor[-1];
          if (IsSpace(delim))
          {
            SkipSpaces(&argCursor);
            delim = *argCursor;
          }
          switch (delim)
          {
            default:
            {
              if (!Eq_string(buf, substring("__user")) && !Eq_string(buf, substring("struct")))
              {
                sawType = true;
                buf = ReplaceLinuxType(buf);
                fprintf(printer->wrapperPrototypesFile, "%.*s ", (int)buf.size, buf.bytes);
                fprintf(printer->wrapperImplementationFile, "%.*s ", (int)buf.size, buf.bytes);
              }
            } break;
            case ',':
            case ')':
            {
              if (sawType)
              {
                // arg name
                assert(argCursor[-2] != ' ');
                fprintf(printer->wrapperPrototypesFile, "%.*s", (int)buf.size, buf.bytes);
                fprintf(printer->wrapperImplementationFile, "%.*s", (int)buf.size, buf.bytes);
                substring argName = buf;
                for (size_t i = 0; i < argName.size; ++i)
                {
                  char c = argName.bytes[i];
                  if (IsAlpha(c) || c == '_')
                  {
                    argName.bytes = argName.bytes + i;
                    argName.size -= i;
                    break;
                  }
                }
                for (size_t i = 0; i < argName.size; ++i)
                {
                  char c = argName.bytes[i];
                  if (!IsAlpha(c) && !IsDigit(c) && c != '_')
                  {
                    argName.size = i;
                    break;
                  }
                }
                argNames[argNamesCount++] = argName;
                sawType = false;
              }
              else
              {
                if (delim != ')')
                {
                  fprintf(stderr, "ERROR: delim != ')' (missing arg name?) for %.*s", (int)slot->prototype.size, slot->prototype.bytes);
                }
                buf = ReplaceLinuxType(buf);
                fprintf(printer->wrapperPrototypesFile, "%.*s", (int)buf.size, buf.bytes);
                fprintf(printer->wrapperImplementationFile, "%.*s", (int)buf.size, buf.bytes);
              }

              if (delim == ',')
              {
                fprintf(printer->wrapperPrototypesFile, ", ");
                fprintf(printer->wrapperImplementationFile, ", ");
              }
            } break;
          }
        } while (delim != ')' && delim != ',');
      } while(cursor[-1] != ')');

      fprintf(printer->wrapperPrototypesFile, ");\n");
      if (printer->disabledWrapper)
      {
        fprintf(printer->wrapperImplementationFile, ");\n");
        printer->disabledWrapper = false;
        printer->customWrapper = 0;
      }
      else
      {
        fprintf(printer->wrapperImplementationFile, ") {\n");
        if (printer->customWrapper)
        {
          fprintf(printer->wrapperImplementationFile, "%s", printer->customWrapper);
          printer->customWrapper = 0;
        }
        else
        {
          fprintf(printer->wrapperImplementationFile, "  return Syscall%d_linux(NR_%.*s_linux", argNamesCount, (int)syscallName.size, syscallName.bytes);
          for (size_t i = 0; i < argNamesCount; ++i)
          {
            fprintf(printer->wrapperImplementationFile, ", %.*s", (int)argNames[i].size, argNames[i].bytes);
          }
          fprintf(printer->wrapperImplementationFile, ", 0);\n");
        }
        fprintf(printer->wrapperImplementationFile, "}\n");
      }
    }
  }

  // syscall table numbers
  PrintAndRemoveSyscall(printer->out, printer->syscallTable, key, printer->dimensions.maxSysIdSize);
  ++printer->linesPrintedSinceLastArchSection;
  printer->state = PRINTED_SYSCALL_table_printer_state;
}

char* cloneWrapper = \
"#if defined(__x86_64__)\n"
"  return Syscall5_linux(NR_clone_linux, clone_flags, newsp,  parent_tidptr, child_tidptr, tls, 0);\n"
"#else\n"
"  return Syscall5_linux(NR_clone_linux, clone_flags, newsp,  parent_tidptr, tls, child_tidptr, 0);\n"
"#endif\n";
char* wait4Wrapper = \
"#if !(defined(__riscv) && (__riscv_xlen == 32))\n"
"  return Syscall4_linux(NR_wait4_linux, pid, stat_addr, options, ru, 0);\n"
"#else\n"
"  int which = P_PID_linux;\n"
"  if (pid < -1) {\n"
"    which = P_PGID_linux;\n"
"    pid = -pid;\n"
"  } else if (pid == -1) {\n"
"    which = P_ALL_linux;\n"
"  } else if (pid == 0) {\n"
"    which = P_PGID_linux;\n"
"  }\n"
"\n"
"  siginfo_t_linux infop;\n"
"  infop.si_pid_linux = 0;\n"
"\n"
"  long ret = Syscall5_linux(NR_waitid_linux, which, pid, &infop, options | WEXITED_linux, ru, 0);\n"
"\n"
"  if (ret >= 0) {\n"
"    ret = infop.si_pid_linux;\n"
"    if (infop.si_pid_linux && stat_addr) {\n"
"      switch (infop.si_code) {\n"
"        case CLD_EXITED_linux: *stat_addr = (infop.si_status_linux & 0xff) << 8; break;\n"
"        case CLD_KILLED_linux: *stat_addr = infop.si_status_linux & 0x7f; break;\n"
"        case CLD_DUMPED_linux: *stat_addr = (infop.si_status_linux & 0x7f) | 0x80; break;\n"
"        case CLD_TRAPPED_linux:\n"
"        case CLD_STOPPED_linux: *stat_addr = (infop.si_status_linux << 8) | 0x7f; break;\n"
"        case CLD_CONTINUED_linux: *stat_addr = 0xffff; break;\n"
"        default: *stat_addr = 0; break;\n"
"      }\n"
"    }\n"
"  }\n"
"\n"
"  return ret;\n"
"#endif\n";

char* sched_rr_get_interval_time64Wrapper = \
"#if defined(__x86_64__) || (defined(__riscv) && (__riscv_xlen == 64))\n"
"  return Syscall2_linux(NR_sched_rr_get_interval_linux, pid, interval, 0);\n"
"#else\n"
"  return Syscall2_linux(NR_sched_rr_get_interval_time64_linux, pid, interval, 0);\n"
"#endif\n";

char* niceWrapper = \
"  long ret = getpriority_linux(PRIO_PROCESS_linux, 0);\n"
"  if (ret < 0) return ret;\n"
"  return setpriority_linux(PRIO_PROCESS_linux, 0, (int)(20 - ret + increment));\n";

void PrintUnifiedSyscallNumbersTableAndWrappers(htable* syscallTable, char* outPath)
{
  int maxSysIdSize = 0;
  for (size_t i = 0; i < syscallTable->capacity; ++i)
  {
    htable_slot* slot = &syscallTable->slots[i];
    if (slot->state == OCCUPIED_htable_slot_state)
    {
      if (slot->key.size > maxSysIdSize)
      {
        maxSysIdSize = slot->key.size;
      }
    }
  }

  printf("syscallTable->size = %zu\n", syscallTable->size);
  printf("\n");

  FILE* file = fopen(outPath, "w");
  FILE* wrapperPrototypesFile = fopen("tables/wrapper_prototypes.h", "w");
  FILE* wrapperImplementationFile = fopen("tables/wrapper_implementations.h", "w");

  assert(file);
  assert(wrapperPrototypesFile);
  assert(wrapperImplementationFile);

  #define PRINT(s) PrintSyscallLine(&printer, s)

  table_dimensions dimensions = Get_table_dimensions(maxSysIdSize);

  printf("maxSysIdSize = %d\n", dimensions.maxSysIdSize);
  printf("tableStart = %d\n", dimensions.tableStart);
  printf("textStart = %d\n", dimensions.textStart);
  printf("defineStart = %d\n", dimensions.defineStart);
  printf("archStart = %d\n", dimensions.archStart);
  printf("tableEnd = %d\n", dimensions.tableEnd);

  table_printer printer = {0};
  printer.out = file;
  printer.wrapperPrototypesFile = wrapperPrototypesFile;
  printer.wrapperImplementationFile = wrapperImplementationFile;
  printer.dimensions = dimensions;
  printer.syscallTable = syscallTable;

  PrintSection(&printer, "PROCESS & THREAD LIFECYCLE", "Creation, execution, termination, and reaping of processes/threads");

  printer.customWrapper = "  return clone_linux(SIGCHLD_linux, 0, 0, 0, 0);\n";
  PRINT("fork");
  printer.customWrapper = "  return clone_linux(CLONE_VFORK_linux | CLONE_VM_linux | SIGCHLD_linux, 0, 0, 0, 0);\n";
  PRINT("vfork");
  printer.customWrapper = cloneWrapper;
  PRINT("clone");
  PRINT("clone3");
  PRINT("execve");
  PRINT("execveat");
  printer.customWrapper = "  Syscall1_linux(NR_exit_linux, error_code, 0);\n  __builtin_unreachable();\n";
  PRINT("exit");
  printer.customWrapper = "  Syscall1_linux(NR_exit_group_linux, error_code, 0);\n  __builtin_unreachable();\n";
  PRINT("exit_group");
  printer.customWrapper = wait4Wrapper;
  PRINT("wait4");
  PRINT("waitid");
  printer.customWrapper = "  return wait4_linux(pid, stat_addr, options, 0);\n";
  PRINT("waitpid");

  PrintSection(&printer, "PROCESS ATTRIBUTES & CONTROL", NULL);
  PrintSubsection(&printer, "Process identity, process groups and sessions");

  PRINT("getpid");
  PRINT("getppid");
  PRINT("gettid");
  PRINT("getpgid");
  PRINT("setpgid");
  printer.customWrapper = "  return getpgid_linux(0);\n";
  PRINT("getpgrp");
  PRINT("getsid");
  PRINT("setsid");
  PRINT("set_tid_address");

  PrintSubsection(&printer, "Process control and personality");

  PRINT("prctl");
  PRINT("personality");

  PrintSection(&printer, "SCHEDULING & PRIORITIES", NULL);

  PRINT("sched_setscheduler");
  PRINT("sched_getscheduler");
  PRINT("sched_setparam");
  PRINT("sched_getparam");
  PRINT("sched_setattr");
  PRINT("sched_getattr");
  PRINT("sched_yield");
  PRINT("sched_get_priority_max");
  PRINT("sched_get_priority_min");
  printer.disabledWrapper = true;
  PRINT("sched_rr_get_interval");
  printer.customWrapper = sched_rr_get_interval_time64Wrapper;
  PRINT("sched_rr_get_interval_time64");
  PRINT("sched_setaffinity");
  PRINT("sched_getaffinity");
  printer.customWrapper = niceWrapper;
  PRINT("nice");
  PRINT("setpriority");
  PRINT("getpriority");

  PrintSection(&printer, "MEMORY MANAGEMENT", NULL);
  PrintSubsection(&printer, "Memory mapping, allocation, and unmapping");

  PRINT("brk");
  PRINT("mmap");
  PRINT("mmap2");
  PRINT("munmap");
  PRINT("mremap");
  PRINT("remap_file_pages");

  PrintSubsection(&printer, "Memory protection, locking, and usage hints");

  PRINT("mprotect");
  PRINT("pkey_mprotect");
  PRINT("madvise");
  PRINT("process_madvise");
  PRINT("mlock");
  PRINT("mlock2");
  PRINT("munlock");
  PRINT("mlockall");
  PRINT("munlockall");
  PRINT("mincore");
  PRINT("msync");
  PRINT("mseal");

  PrintSubsection(&printer, "NUMA memory policy and page migration");

  PRINT("mbind");
  PRINT("set_mempolicy");
  PRINT("get_mempolicy");
  PRINT("set_mempolicy_home_node");
  PRINT("migrate_pages");
  PRINT("move_pages");

  PrintSubsection(&printer, "Anonymous file-backed memory regions");

  PRINT("memfd_create");
  PRINT("memfd_secret");

  PrintSubsection(&printer, "Memory protection key management");

  PRINT("pkey_alloc");
  PRINT("pkey_free");

  PrintSubsection(&printer, "Control-flow integrity, shadow stack mapping");

  PRINT("map_shadow_stack");

  PrintSubsection(&printer, "Advanced memory operations");

  PRINT("userfaultfd");
  PRINT("process_mrelease");
  PRINT("membarrier");

  PrintSection(&printer, "FILE I/O OPERATIONS", NULL);
  PrintSubsection(&printer, "Opening, creating, and closing files");

  PRINT("open");
  PRINT("openat");
  PRINT("openat2");
  PRINT("creat");
  PRINT("close");
  PRINT("close_range");
  PRINT("open_by_handle_at");
  PRINT("name_to_handle_at");

  PrintSubsection(&printer, "Reading and writing file data");

  PRINT("read");
  PRINT("write");
  PRINT("readv");
  PRINT("writev");
  PRINT("pread64");
  PRINT("pwrite64");
  PRINT("preadv");
  PRINT("pwritev");
  PRINT("preadv2");
  PRINT("pwritev2");

  PrintSubsection(&printer, "Seeking and truncating files");

  PRINT("lseek");
  PRINT("llseek");
  PRINT("_llseek");
  PRINT("truncate");
  PRINT("truncate64");
  PRINT("ftruncate");
  PRINT("ftruncate64");

  PrintSubsection(&printer, "Zero-copy and specialized I/O");

  PRINT("sendfile");
  PRINT("sendfile64");
  PRINT("splice");
  PRINT("tee");
  PRINT("vmsplice");
  PRINT("copy_file_range");

  PrintSubsection(&printer, "I/O hints and space allocation");

  PRINT("fadvise64");
  PRINT("fadvise64_64");
  PRINT("arm_fadvise64_64");
  PRINT("readahead");
  PRINT("fallocate");

  PrintSubsection(&printer, "Flushing file data to storage");

  PRINT("sync");
  PRINT("syncfs");
  PRINT("fsync");
  PRINT("fdatasync");
  PRINT("sync_file_range");
  PRINT("arm_sync_file_range");

  PrintSection(&printer, "FILE DESCRIPTOR MANAGEMENT", NULL);
  PrintSubsection(&printer, "Duplicating and controlling file descriptors");

  PRINT("dup");
  PRINT("dup2");
  PRINT("dup3");
  PRINT("fcntl");
  PRINT("fcntl64");

  PrintSubsection(&printer, "Device-specific control operations");

  PRINT("ioctl");

  PrintSubsection(&printer, "I/O Multiplexing");

  PRINT("select");
  PRINT("_newselect");
  printer.disabledWrapper = true;
  PRINT("pselect6");
  PRINT("pselect6_time64");
  PRINT("poll");
  printer.disabledWrapper = true;
  PRINT("ppoll");
  PRINT("ppoll_time64");

  PrintSubsection(&printer, "Scalable I/O event notification");

  PRINT("epoll_create");
  PRINT("epoll_create1");
  PRINT("epoll_ctl");
  PRINT("epoll_wait");
  PRINT("epoll_pwait");
  PRINT("epoll_pwait2");
  PRINT("epoll_ctl_old");
  PRINT("epoll_wait_old");

  PrintSection(&printer, "FILE METADATA", NULL);
  PrintSubsection(&printer, "Getting file attributes and status");

  PRINT("stat");
  PRINT("fstat");
  PRINT("lstat");
  PRINT("stat64");
  PRINT("fstat64");
  PRINT("lstat64");
  PRINT("newfstatat");
  PRINT("fstatat64");
  PRINT("statx");
  PRINT("oldstat");
  PRINT("oldfstat");
  PRINT("oldlstat");
  PRINT("file_getattr");

  PrintSubsection(&printer, "Changing file permissions and ownership");

  PRINT("chmod");
  PRINT("fchmod");
  PRINT("fchmodat");
  PRINT("fchmodat2");
  PRINT("umask");
  PRINT("chown");
  PRINT("fchown");
  PRINT("lchown");
  PRINT("chown32");
  PRINT("fchown32");
  PRINT("lchown32");
  PRINT("fchownat");
  PRINT("file_setattr");

  PrintSubsection(&printer, "File access and modification times");

  PRINT("utime");
  PRINT("utimes");
  PRINT("futimesat");
  printer.disabledWrapper = true;
  PRINT("utimensat");
  PRINT("utimensat_time64");

  PrintSubsection(&printer, "Testing file accessibility");

  PRINT("access");
  PRINT("faccessat");
  PRINT("faccessat2");

  PrintSubsection(&printer, "Getting, setting, and listing extended attributes");

  PRINT("setxattr");
  PRINT("lsetxattr");
  PRINT("fsetxattr");
  PRINT("setxattrat");
  PRINT("getxattr");
  PRINT("lgetxattr");
  PRINT("fgetxattr");
  PRINT("getxattrat");
  PRINT("listxattr");
  PRINT("llistxattr");
  PRINT("flistxattr");
  PRINT("listxattrat");
  PRINT("removexattr");
  PRINT("lremovexattr");
  PRINT("fremovexattr");
  PRINT("removexattrat");

  PrintSubsection(&printer, "Advisory file locking");

  PRINT("flock");

  PrintSection(&printer, "DIRECTORY & NAMESPACE OPERATIONS", NULL);
  PrintSubsection(&printer, "Creating, removing, and reading directories");

  PRINT("mkdir");
  PRINT("mkdirat");
  PRINT("rmdir");
  PRINT("getdents");
  PRINT("getdents64");
  PRINT("readdir");

  PrintSubsection(&printer, "Getting and changing current directory");

  PRINT("getcwd");
  PRINT("chdir");
  PRINT("fchdir");

  PrintSubsection(&printer, "Creating and managing hard and symbolic links");

  PRINT("link");
  PRINT("linkat");
  PRINT("unlink");
  PRINT("unlinkat");
  PRINT("symlink");
  PRINT("symlinkat");
  PRINT("readlink");
  PRINT("readlinkat");
  PRINT("rename");
  PRINT("renameat");
  PRINT("renameat2");

  PrintSubsection(&printer, "Creating device and named pipe nodes");

  PRINT("mknod");
  PRINT("mknodat");

  PrintSection(&printer, "FILE SYSTEM OPERATIONS", NULL);
  PrintSubsection(&printer, "Mounting filesystems and changing root");

  PRINT("mount");
  PRINT("umount");
  PRINT("umount2");
  PRINT("pivot_root");
  PRINT("chroot");
  PRINT("mount_setattr");
  PRINT("move_mount");
  PRINT("open_tree");
  PRINT("open_tree_attr");
  PRINT("fsconfig");
  PRINT("fsmount");
  PRINT("fsopen");
  PRINT("fspick");

  PrintSubsection(&printer, "Getting filesystem statistics");

  PRINT("statfs");
  PRINT("fstatfs");
  PRINT("statfs64");
  PRINT("fstatfs64");
  PRINT("ustat");
  PRINT("statmount");
  PRINT("listmount");

  PrintSubsection(&printer, "Disk quota control");

  PRINT("quotactl");
  PRINT("quotactl_fd");

  PrintSection(&printer, "FILE SYSTEM MONITORING", NULL);
  PrintSubsection(&printer, "Monitoring filesystem events");

  PRINT("inotify_init");
  PRINT("inotify_init1");
  PRINT("inotify_add_watch");
  PRINT("inotify_rm_watch");

  PrintSubsection(&printer, "Filesystem-wide event notification");

  PRINT("fanotify_init");
  PRINT("fanotify_mark");

  PrintSection(&printer, "SIGNALS", NULL);
  PrintSubsection(&printer, "Setting up signal handlers");

  PRINT("signal");
  PRINT("sigaction");
  PRINT("rt_sigaction");

  PrintSubsection(&printer, "Sending signals to processes");

  PRINT("kill");
  PRINT("tkill");
  PRINT("tgkill");
  PRINT("rt_sigqueueinfo");
  PRINT("rt_tgsigqueueinfo");

  PrintSubsection(&printer, "Blocking and unblocking signals");

  PRINT("sigprocmask");
  PRINT("rt_sigprocmask");
  PRINT("sgetmask");
  PRINT("ssetmask");

  PrintSubsection(&printer, "Waiting for and querying signals");

  PRINT("sigpending");
  PRINT("rt_sigpending");
  PRINT("sigsuspend");
  PRINT("rt_sigsuspend");
  PRINT("pause");
  printer.disabledWrapper = true;
  PRINT("rt_sigtimedwait");
  PRINT("rt_sigtimedwait_time64");

  PrintSubsection(&printer, "Alternate signal stack and return from handlers");

  PRINT("sigaltstack");
  PRINT("sigreturn");
  PRINT("rt_sigreturn");

  PrintSubsection(&printer, "Signal delivery via file descriptors");

  PRINT("signalfd");
  PRINT("signalfd4");

  PrintSection(&printer, "PIPES & FIFOs", NULL);

  PRINT("pipe");
  PRINT("pipe2");

  PrintSection(&printer, "INTER-PROCESS COMMUNICATION", NULL);
  PrintSubsection(&printer, "System V IPC - Shared Memory");

  PRINT("shmget");
  PRINT("shmat");
  PRINT("shmdt");
  PRINT("shmctl");

  PrintSubsection(&printer, "System V IPC - Message Queues");

  PRINT("msgget");
  PRINT("msgsnd");
  PRINT("msgrcv");
  PRINT("msgctl");

  PrintSubsection(&printer, "System V IPC - Semaphores");

  PRINT("semget");
  PRINT("semop");
  PRINT("semctl");
  printer.disabledWrapper = true;
  PRINT("semtimedop");
  PRINT("semtimedop_time64");

  PrintSubsection(&printer, "POSIX Message Queues");

  PRINT("mq_open");
  PRINT("mq_unlink");
  printer.disabledWrapper = true;
  PRINT("mq_timedsend");
  PRINT("mq_timedsend_time64");
  printer.disabledWrapper = true;
  PRINT("mq_timedreceive");
  PRINT("mq_timedreceive_time64");
  PRINT("mq_notify");
  PRINT("mq_getsetattr");

  PrintSubsection(&printer, "Synchronization Primitives - Futexes");

  printer.disabledWrapper = true;
  PRINT("futex");
  PRINT("futex_time64");
  PRINT("futex_wait");
  PRINT("futex_wake");
  PRINT("futex_waitv");
  PRINT("futex_requeue");
  PRINT("set_robust_list");
  PRINT("get_robust_list");

  PrintSubsection(&printer, "Synchronization Primitives - Event Notification");

  PRINT("eventfd");
  PRINT("eventfd2");

  PrintSection(&printer, "SOCKETS & NETWORKING", NULL);
  PrintSubsection(&printer, "Creating and configuring sockets");

  PRINT("socket");
  PRINT("socketpair");
  PRINT("bind");
  PRINT("listen");
  PRINT("accept");
  PRINT("accept4");
  PRINT("connect");
  PRINT("shutdown");
  PRINT("socketcall");

  PrintSubsection(&printer, "Sending and receiving data on sockets");

  PRINT("send");
  PRINT("sendto");
  PRINT("sendmsg");
  PRINT("sendmmsg");
  PRINT("recv");
  PRINT("recvfrom");
  PRINT("recvmsg");
  printer.disabledWrapper = true;
  PRINT("recvmmsg");
  PRINT("recvmmsg_time64");

  PrintSubsection(&printer, "Getting and setting socket options");

  PRINT("getsockopt");
  PRINT("setsockopt");
  PRINT("getsockname");
  PRINT("getpeername");

  PrintSection(&printer, "ASYNCHRONOUS I/O", NULL);
  PrintSubsection(&printer, "AIO: asynchronous I/O interface");

  PRINT("io_setup");
  PRINT("io_destroy");
  PRINT("io_submit");
  PRINT("io_cancel");
  PRINT("io_getevents");
  printer.disabledWrapper = true;
  PRINT("io_pgetevents");
  PRINT("io_pgetevents_time64");

  PrintSubsection(&printer, "io_uring: high-performance asynchronous I/O");

  PRINT("io_uring_setup");
  PRINT("io_uring_enter");
  PRINT("io_uring_register");

  PrintSection(&printer, "TIME & CLOCKS", NULL);
  PrintSubsection(&printer, "Reading current time from various clocks");

  PRINT("time");
  PRINT("gettimeofday");
  printer.disabledWrapper = true;
  PRINT("clock_gettime");
  PRINT("clock_gettime64");
  printer.disabledWrapper = true;
  PRINT("clock_getres");
  PRINT("clock_getres_time64");

  PrintSubsection(&printer, "Setting system time and adjusting clocks");

  PRINT("settimeofday");
  printer.disabledWrapper = true;
  PRINT("clock_settime");
  PRINT("clock_settime64");
  PRINT("stime");
  PRINT("adjtimex");
  PRINT("clock_adjtime");
  PRINT("clock_adjtime64");

  PrintSubsection(&printer, "Suspending execution for a period of time");

  PRINT("nanosleep");
  printer.disabledWrapper = true;
  PRINT("clock_nanosleep");
  PRINT("clock_nanosleep_time64");

  PrintSubsection(&printer, "Setting periodic or one-shot timers");

  PRINT("alarm");
  PRINT("setitimer");
  PRINT("getitimer");

  PrintSubsection(&printer, "Per-process timers with precise control");

  PRINT("timer_create");
  printer.disabledWrapper = true;
  PRINT("timer_settime");
  PRINT("timer_settime64");
  printer.disabledWrapper = true;
  PRINT("timer_gettime");
  PRINT("timer_gettime64");
  PRINT("timer_getoverrun");
  PRINT("timer_delete");

  PrintSubsection(&printer, "Timers accessible via file descriptors");

  PRINT("timerfd_create");
  printer.disabledWrapper = true;
  PRINT("timerfd_settime");
  PRINT("timerfd_settime64");
  printer.disabledWrapper = true;
  PRINT("timerfd_gettime");
  PRINT("timerfd_gettime64");

  PrintSection(&printer, "RANDOM NUMBERS", NULL);

  PRINT("getrandom");

  PrintSection(&printer, "USER & GROUP IDENTITY", NULL);
  PrintSubsection(&printer, "Getting and setting user IDs");

  PRINT("getuid");
  PRINT("geteuid");
  PRINT("setuid");
  PRINT("setreuid");
  PRINT("setresuid");
  PRINT("getresuid");
  PRINT("setfsuid");
  PRINT("getuid32");
  PRINT("geteuid32");
  PRINT("setuid32");
  PRINT("setreuid32");
  PRINT("setresuid32");
  PRINT("getresuid32");
  PRINT("setfsuid32");

  PrintSubsection(&printer, "Getting and setting group IDs");

  PRINT("getgid");
  PRINT("getegid");
  PRINT("setgid");
  PRINT("setregid");
  PRINT("setresgid");
  PRINT("getresgid");
  PRINT("setfsgid");
  PRINT("getgid32");
  PRINT("getegid32");
  PRINT("setgid32");
  PRINT("setregid32");
  PRINT("setresgid32");
  PRINT("getresgid32");
  PRINT("setfsgid32");

  PrintSubsection(&printer, "Managing supplementary group list");

  PRINT("getgroups");
  PRINT("setgroups");
  PRINT("getgroups32");
  PRINT("setgroups32");

  PrintSection(&printer, "CAPABILITIES & SECURITY", NULL);
  PrintSubsection(&printer, "Fine-grained privilege control");

  PRINT("capget");
  PRINT("capset");

  PrintSubsection(&printer, "Syscall filtering and sandboxing");

  PRINT("seccomp");

  PrintSubsection(&printer, "Linux Security Module interfaces");

  PRINT("security");
  PRINT("lsm_get_self_attr");
  PRINT("lsm_set_self_attr");
  PRINT("lsm_list_modules");

  PrintSubsection(&printer, "Unprivileged access control");

  PRINT("landlock_create_ruleset");
  PRINT("landlock_add_rule");
  PRINT("landlock_restrict_self");

  PrintSubsection(&printer, "Kernel key retention service");

  PRINT("add_key");
  PRINT("request_key");
  PRINT("keyctl");

  PrintSection(&printer, "RESOURCE LIMITS & ACCOUNTING", NULL);
  PrintSubsection(&printer, "Getting and setting process resource limits");

  PRINT("getrlimit");
  PRINT("setrlimit");
  PRINT("prlimit64");
  PRINT("ugetrlimit");
  PRINT("ulimit");

  PrintSubsection(&printer, "Getting resource usage and time statistics");

  PRINT("getrusage");
  PRINT("times");

  PrintSubsection(&printer, "System-wide process accounting");

  PRINT("acct");

  PrintSection(&printer, "NAMESPACES & CONTAINERS", NULL);

  PRINT("unshare");
  PRINT("setns");
  PRINT("listns");

  PrintSection(&printer, "PROCESS INSPECTION & CONTROL", NULL);
  PrintSubsection(&printer, "Process comparison");

  PRINT("kcmp");

  PrintSubsection(&printer, "Process file descriptors");

  PRINT("pidfd_open");
  PRINT("pidfd_getfd");
  PRINT("pidfd_send_signal");

  PrintSubsection(&printer, "Process memory access");

  PRINT("process_vm_readv");
  PRINT("process_vm_writev");

  PrintSubsection(&printer, "Process tracing");

  PRINT("ptrace");

  PrintSection(&printer, "SYSTEM INFORMATION", NULL);
  PrintSubsection(&printer, "System name and domain information");

  PRINT("uname");
  PRINT("olduname");
  PRINT("oldolduname");
  PRINT("gethostname");
  PRINT("sethostname");
  PRINT("setdomainname");

  PrintSubsection(&printer, "Overall system information and statistics");

  PRINT("sysinfo");

  PrintSubsection(&printer, "Reading kernel log messages");

  PRINT("syslog");

  PrintSubsection(&printer, "Getting CPU and NUMA node information");

  PRINT("getcpu");

  PrintSubsection(&printer, "Kernel filesystem information interface");

  PRINT("sysfs");

  PrintSection(&printer, "KERNEL MODULES", "Loading, unloading, and querying kernel modules");

  PRINT("create_module");
  PRINT("init_module");
  PRINT("finit_module");
  PRINT("delete_module");
  PRINT("query_module");
  PRINT("get_kernel_syms");

  PrintSection(&printer, "SYSTEM CONTROL & ADMINISTRATION", NULL);
  PrintSubsection(&printer, "Rebooting and shutting down the system");

  PRINT("reboot");

  PrintSubsection(&printer, "Enabling and disabling swap areas");

  PRINT("swapon");
  PRINT("swapoff");

  PrintSubsection(&printer, "Loading and executing new kernels");

  PRINT("kexec_load");
  PRINT("kexec_file_load");

  PrintSubsection(&printer, "Other system administration operations");

  PRINT("vhangup");

  PrintSection(&printer, "PERFORMANCE MONITORING & TRACING", NULL);
  PrintSubsection(&printer, "Hardware and software performance monitoring");

  PRINT("perf_event_open");

  PrintSubsection(&printer, "Userspace dynamic tracing");

  PRINT("uprobe");
  PRINT("uretprobe");

  PrintSubsection(&printer, "Programmable Kernel Extensions (eBPF)");

  PRINT("bpf");

  PrintSection(&printer, "DEVICE & HARDWARE ACCESS", NULL);
  PrintSubsection(&printer, "Direct hardware I/O port access");

  PRINT("ioperm");
  PRINT("iopl");

  PrintSubsection(&printer, "Setting I/O scheduling priority");

  PRINT("ioprio_set");
  PRINT("ioprio_get");

  PrintSubsection(&printer, "PCI device configuration access");

  PRINT("pciconfig_read");
  PRINT("pciconfig_write");
  PRINT("pciconfig_iobase");

  PrintSubsection(&printer, "CPU cache control operations");

  PRINT("cacheflush");
  PRINT("cachestat");

  PrintSection(&printer, "ARCHITECTURE-SPECIFIC OPERATIONS", NULL);
  PrintSubsection(&printer, "x86 architecture operations");

  PRINT("arch_prctl");
  PRINT("modify_ldt");
  PRINT("set_thread_area");
  PRINT("get_thread_area");
  PRINT("vm86");
  PRINT("vm86old");

  PrintSubsection(&printer, "ARM architecture operations");

  PRINT("set_tls");
  PRINT("get_tls");

  PrintSubsection(&printer, "RISC-V architecture operations");

  PRINT("riscv_flush_icache");
  PRINT("riscv_hwprobe");

  PrintSubsection(&printer, "Intel MPX support (deprecated)");

  PRINT("mpx");

  PrintSection(&printer, "ADVANCED EXECUTION CONTROL", NULL);
  PrintSubsection(&printer, "Restartable sequences");

  PRINT("rseq");

  PrintSubsection(&printer, "Restart syscall");

  PRINT("restart_syscall");

  PrintSubsection(&printer, "Directory entry cache");

  PRINT("lookup_dcookie");

  PrintSection(&printer, "LEGACY, OBSOLETE & UNIMPLEMENTED", NULL);

  PRINT("_sysctl");
  PRINT("ipc");
  PRINT("profil");
  PRINT("prof");
  PRINT("afs_syscall");
  PRINT("break");
  PRINT("ftime");
  PRINT("gtty");
  PRINT("idle");
  PRINT("lock");
  PRINT("nfsservctl");
  PRINT("getpmsg");
  PRINT("putpmsg");
  PRINT("stty");
  PRINT("tuxcall");
  PRINT("vserver");
  PRINT("bdflush");
  PRINT("uselib");

  PrintTableSeparatorLine(file, "═", &dimensions);
  PrintTableTextLineCentered(file, "generated by https://github.com/t-cadet/c-resources/blob/main/linux/get_syscall_tables.c", &dimensions);
  PrintTableBottomLine(file, &dimensions);

  PrintTableSummary(&printer);

  int syscallsNotInTable = 0;
  for (size_t i = 0; i < syscallTable->capacity; ++i)
  {
    htable_slot* slot = &syscallTable->slots[i];
    if (slot->state == OCCUPIED_htable_slot_state)
    {
      ++syscallsNotInTable;
      PrintAndRemoveSyscall(file, syscallTable, slot->key, maxSysIdSize);
    }
  }

  printf("syscallTable->size = %zu\n", syscallTable->size);
  assert(syscallsNotInTable == 0);

  fclose(file);
  fclose(wrapperPrototypesFile);
  fclose(wrapperImplementationFile);
}

int main()
{
  htable syscallTable = {0};

  arch archs[SIZE_arch_id] = {0};

  archs[X86_64_arch_id]   = (arch) { .archId = X86_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_64.tbl", .outPath = "tables/x86_64_syscall_table.h" };
  archs[ARM_64_arch_id]   = (arch) { .archId = ARM_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm64/tools/syscall_64.tbl"       , .outPath = "tables/arm64_syscall_table.h" };
  archs[RISCV_64_arch_id] = (arch) { .archId = RISCV_64_arch_id, .inPath   = LINUX_ROOT "scripts/syscall.tbl"             , .outPath = "tables/riscv64_syscall_table.h" };
  archs[X86_32_arch_id]   = (arch) { .archId = X86_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_32.tbl", .outPath = "tables/x86_32_syscall_table.h" };
  archs[ARM_32_arch_id]   = (arch) { .archId = ARM_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm/tools/syscall.tbl"            , .outPath = "tables/arm32_syscall_table.h" };
  archs[RISCV_32_arch_id] = (arch) { .archId = RISCV_32_arch_id, .inPath   = LINUX_ROOT "scripts/syscall.tbl"             , .outPath = "tables/riscv32_syscall_table.h" };

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    LoadSyscallNumbers(arch, &syscallTable);
    PrintSyscallNumbersSorted(arch, &syscallTable);
  }

  char* prototypesBytes = LoadSyscallPrototypes(&syscallTable, LINUX_ROOT "include/linux/syscalls.h");

  PrintUnifiedSyscallNumbersTableAndWrappers(&syscallTable, "tables/cross_architecture_syscall_table.h");

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    Free_arch(arch);
  }
  Free_htable(&syscallTable);
  free(prototypesBytes);
}

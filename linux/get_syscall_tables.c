// clang -std=c23 -ggdb get_syscall_tables.c -o get_syscall_tables && ./get_syscall_tables
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

#define GLIBC_SYSV "/home/tcadet/dev/open-source/glibc/sysdeps/unix/sysv/linux/"
#define LINUX_ARCH_ROOT "/home/tcadet/dev/open-source/linux/arch/"

#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#define DEFINE ((substring){ .bytes = "#define", .size = strlen("#define") })
#define substring(string) ((substring){ .bytes = string, .size = strlen(string) })

bool streq(char* a, char* b)
{
  return strcmp(a, b) == 0;
}

enum arch_id
{
  ARM_32_arch_id = 0,
  ARM_64_arch_id,
  RISCV_32_arch_id,
  RISCV_64_arch_id,
  X86_32_arch_id,
  X86_64_arch_id,

  SIZE_arch_id
};

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

struct
{
  substring key;
  int value[SIZE_arch_id];
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

bool IsEmpty_slot(htable_slot* slot)
{
  return slot->key.bytes == 0;
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
    if (Eq_string(slot->key, key))
    {
      out = slot;
      break;
    }
    else if (IsEmpty_slot(slot))
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
    if (Eq_string(slot->key, key))
    {
      out = slot;
      break;
    }
    else if (IsEmpty_slot(slot))
    {
      slot->key = key;
      out = slot;
      ++table->size;
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
      if (!IsEmpty_slot(slot))
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
    htable_slot** pivot = &table_->items[0];
    size_t stop = table_->size;
    for (size_t i = 1; i < stop; ++i)
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
  bool glibc;
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
        delimiterMatches = *bytes[i] == delimiter[i];
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

bool Read_syscall_number_line(char** bytes, syscall_number_line* outLine, bool glibc)
{


  bool success = false;
  if (bytes && *bytes)
  {
    char* cursor = *bytes;
    syscall_number_line line = {0};
    if (glibc)
    {
      success = ReadUntilOneOf(&cursor, " \n", &line.callingConvention)
             && Eq_string(line.callingConvention, DEFINE)
             && ReadUntilOneOf(&cursor, " \n", &line.sysId)
             && Read_int(&cursor, &line.sysNr)
             && ReadUntil(&cursor, "\n", 0);
      if (success)
      {
        assert(line.sysId.size > 5);
        assert(line.sysId.bytes[0] == '_');
        assert(line.sysId.bytes[1] == '_');
        assert(line.sysId.bytes[2] == 'N');
        assert(line.sysId.bytes[3] == 'R');
        assert(line.sysId.bytes[4] == '_');

        line.sysId.bytes += 5;
        line.sysId.size -= 5;
      }
    }
    else
    {
      success = Read_int(&cursor, &line.sysNr)
             && ReadUntil(&cursor, "\t", 0)
             // renameat is separated by a space (typo?) so we look for that too
             && ReadUntilOneOf(&cursor, "\t ", &line.callingConvention);
      // handle lines that end after the 3rd column
      char* cursor2 = cursor;
      success = success
             && ReadUntilOneOf(&cursor2, "\t\n", &line.sysId)
             && ReadUntil(&cursor, "\n", 0);
    }
    if (Eq_string(line.callingConvention, substring("csky"))
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
    if (Read_syscall_number_line(&cursor, &line, arch->glibc))
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
  }

  // printf("\n");
}

void PrintSyscallNumbersSorted(arch* arch, htable* syscallTable)
{
  table sortedSyscalls = {0};
  for (size_t i = 0; i < syscallTable->capacity; ++i)
  {
    htable_slot* slot = &syscallTable->slots[i];
    if (!IsEmpty_slot(slot))
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
      if (arch->archId == ARM_32_arch_id &&
         (Eq_string(slot->key, substring("cacheflush"))
       || Eq_string(slot->key, substring("set_tls"))
       || Eq_string(slot->key, substring("get_tls"))))
      {
        fprintf(file, "#define __NR_%.*s %#08x\n", (int)slot->key.size, slot->key.bytes, sysNr);
      }
      else
      {
        fprintf(file, "#define __NR_%.*s %d\n", (int)slot->key.size, slot->key.bytes, sysNr);
      }
    }
  }

  Free_table(&sortedSyscalls);
  assert(fwrite("\n", 1, 1, file) == 1);
  fclose(file);
}

void PrintUnifiedSyscallNumbersTable(arch* archs, size_t archsSize)
{
}

int main()
{
  htable syscallTable = {0};
  
  arch archs[SIZE_arch_id] = {0};

  archs[ARM_32_arch_id]   = (arch) { .archId = ARM_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm/tools/syscall.tbl"            , .outPath = "tables/arm32_syscall_table.h" };
  archs[ARM_64_arch_id]   = (arch) { .archId = ARM_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm64/tools/syscall_64.tbl"       , .outPath = "tables/arm64_syscall_table.h" };
  archs[RISCV_32_arch_id] = (arch) { .archId = RISCV_32_arch_id, .inPath   = GLIBC_SYSV "riscv/rv32/arch-syscall.h"             , .outPath = "tables/riscv32_syscall_table.h", .glibc = true };
  archs[RISCV_64_arch_id] = (arch) { .archId = RISCV_64_arch_id, .inPath   = GLIBC_SYSV "riscv/rv64/arch-syscall.h"             , .outPath = "tables/riscv64_syscall_table.h", .glibc = true };
  archs[X86_32_arch_id]   = (arch) { .archId = X86_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_32.tbl", .outPath = "tables/x86_32_syscall_table.h" };
  archs[X86_64_arch_id]   = (arch) { .archId = X86_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_64.tbl", .outPath = "tables/x86_64_syscall_table.h" };

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    LoadSyscallNumbers(arch, &syscallTable);
    PrintSyscallNumbersSorted(arch, &syscallTable);
  }

  PrintUnifiedSyscallNumbersTable(archs, sizeof(archs));

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    Free_arch(arch);
  }
  Free_htable(&syscallTable);
}

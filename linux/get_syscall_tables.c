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
    if (Eq_string(slot->key, key))
    {
      out = slot;
      break;
    }
    else if (slot->state == EMPTY_htable_slot_state
          || slot->state == REMOVED_htable_slot_state)
    {
      slot->key = key;
      slot->state = OCCUPIED_htable_slot_state;
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
  dimensions.archStart = dimensions.defineStart + strlen("#define NR_") + dimensions.maxSysIdSize + strlen("_linux ") + strlen("BY_ARCH");
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
    fprintf(file, "BY_ARCH( ");
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
  table_dimensions dimensions;
  htable* syscallTable;

  enum table_printer_state state;
  int sectionNumber;
  char subsectionLetter;

  int linesPrintedSinceLastArchSection;

  char* sectionTitles[MAX_SESSION_TITLES];
  int sectionTitlesCount;
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

  PrintTableSeparatorLineEx(printer->out, "─", "─", "─", &printer->dimensions);
  ++printer->linesPrintedSinceLastArchSection;

  printer->state = PRINTED_SECTION_table_printer_state;
  ++printer->subsectionLetter;

  assert(printer->subsectionLetter <= 'z');
}

void PrintSyscallLine(table_printer* printer, char* s) {
  assert(printer->state != PRINTED_NOTHING_table_printer_state);
  PrintAndRemoveSyscall(printer->out, printer->syscallTable, substring(s), printer->dimensions.maxSysIdSize);
  ++printer->linesPrintedSinceLastArchSection;
  printer->state = PRINTED_SYSCALL_table_printer_state;
}

void PrintUnifiedSyscallNumbersTable(htable* syscallTable, char* outPath)
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
  assert(file);

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
  printer.dimensions = dimensions;
  printer.syscallTable = syscallTable;

  PrintSection(&printer, "PROCESS & THREAD LIFECYCLE", "Creation, execution, termination, and reaping of processes/threads");

  PRINT("fork");
  PRINT("vfork");
  PRINT("clone");
  PRINT("clone3");
  PRINT("execve");
  PRINT("execveat");
  PRINT("exit");
  PRINT("exit_group");
  PRINT("wait4");
  PRINT("waitid");
  PRINT("waitpid");

  PrintSection(&printer, "PROCESS ATTRIBUTES & CONTROL", NULL);
  PrintSubsection(&printer, "Process identity, process groups and sessions");

  PRINT("getpid");
  PRINT("getppid");
  PRINT("gettid");
  PRINT("getpgid");
  PRINT("setpgid");
  PRINT("getpgrp");
  PRINT("getsid");
  PRINT("setsid");
  PRINT("set_tid_address");

  PrintSubsection(&printer, "Process control, personality, and miscellaneous attributes");

  PRINT("prctl");
  PRINT("personality");
  PRINT("arch_prctl");
  PRINT("modify_ldt");
  PRINT("set_thread_area");
  PRINT("get_thread_area");
  PRINT("set_tls");
  PRINT("get_tls");

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
  PRINT("sched_rr_get_interval");
  PRINT("sched_rr_get_interval_time64");
  PRINT("sched_setaffinity");
  PRINT("sched_getaffinity");
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
  PRINT("pselect6");
  PRINT("pselect6_time64");
  PRINT("poll");
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
  PRINT("semtimedop");
  PRINT("semtimedop_time64");

  PrintSubsection(&printer, "POSIX Message Queues");

  PRINT("mq_open");
  PRINT("mq_unlink");
  PRINT("mq_timedsend");
  PRINT("mq_timedsend_time64");
  PRINT("mq_timedreceive");
  PRINT("mq_timedreceive_time64");
  PRINT("mq_notify");
  PRINT("mq_getsetattr");

  PrintSubsection(&printer, "Synchronization Primitives - Futexes");

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
  PRINT("clock_gettime");
  PRINT("clock_gettime64");
  PRINT("clock_getres");
  PRINT("clock_getres_time64");

  PrintSubsection(&printer, "Setting system time and adjusting clocks");

  PRINT("settimeofday");
  PRINT("clock_settime");
  PRINT("clock_settime64");
  PRINT("stime");
  PRINT("adjtimex");
  PRINT("clock_adjtime");
  PRINT("clock_adjtime64");

  PrintSubsection(&printer, "Suspending execution for a period of time");

  PRINT("nanosleep");
  PRINT("clock_nanosleep");
  PRINT("clock_nanosleep_time64");

  PrintSubsection(&printer, "Setting periodic or one-shot timers");

  PRINT("alarm");
  PRINT("setitimer");
  PRINT("getitimer");

  PrintSubsection(&printer, "Per-process timers with precise control");

  PRINT("timer_create");
  PRINT("timer_settime");
  PRINT("timer_settime64");
  PRINT("timer_gettime");
  PRINT("timer_gettime64");
  PRINT("timer_getoverrun");
  PRINT("timer_delete");

  PrintSubsection(&printer, "Timers accessible via file descriptors");

  PRINT("timerfd_create");
  PRINT("timerfd_settime");
  PRINT("timerfd_settime64");
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
  PrintSubsection(&printer, "RISC-V architecture operations");

  PRINT("riscv_flush_icache");
  PRINT("riscv_hwprobe");

  PrintSubsection(&printer, "x86 architecture operations");

  PRINT("vm86");
  PRINT("vm86old");

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
}

int main()
{
  htable syscallTable = {0};

  arch archs[SIZE_arch_id] = {0};

  archs[X86_64_arch_id]   = (arch) { .archId = X86_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_64.tbl", .outPath = "tables/x86_64_syscall_table.h" };
  archs[ARM_64_arch_id]   = (arch) { .archId = ARM_64_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm64/tools/syscall_64.tbl"       , .outPath = "tables/arm64_syscall_table.h" };
  archs[RISCV_64_arch_id] = (arch) { .archId = RISCV_64_arch_id, .inPath   = GLIBC_SYSV "riscv/rv64/arch-syscall.h"             , .outPath = "tables/riscv64_syscall_table.h", .glibc = true };
  archs[X86_32_arch_id]   = (arch) { .archId = X86_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "x86/entry/syscalls/syscall_32.tbl", .outPath = "tables/x86_32_syscall_table.h" };
  archs[ARM_32_arch_id]   = (arch) { .archId = ARM_32_arch_id  , .inPath   = LINUX_ARCH_ROOT "arm/tools/syscall.tbl"            , .outPath = "tables/arm32_syscall_table.h" };
  archs[RISCV_32_arch_id] = (arch) { .archId = RISCV_32_arch_id, .inPath   = GLIBC_SYSV "riscv/rv32/arch-syscall.h"             , .outPath = "tables/riscv32_syscall_table.h", .glibc = true };

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    LoadSyscallNumbers(arch, &syscallTable);
    PrintSyscallNumbersSorted(arch, &syscallTable);
  }

  PrintUnifiedSyscallNumbersTable(&syscallTable, "tables/cross_platform_syscall_table.h");

  for (int archId = 0; archId < ARRAY_SIZE(archs); ++archId)
  {
    arch* arch = archs + archId;
    Free_arch(arch);
  }
  Free_htable(&syscallTable);
}

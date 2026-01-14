#include <stdio.h>  // for getc, printf
#include <stdlib.h> // malloc, free
#include "ijvm.h"
#include "util.h" // read this file for debug prints, endianness helper functions
#include <string.h>
#include <signal.h>
#include <stdbool.h>

bool snapshot =false;

void take_snapshot(ijvm* m) {
    FILE* snap_file = fopen("snapshot.bin", "wb");
    if (snap_file == NULL) {
        perror("Could not open snapshot snap_file");
        return;
    }
    fwrite(&m->program_counter, sizeof(uint32_t), 1, snap_file);
    fwrite(&m->cp_size, sizeof(uint32_t), 1, snap_file);
    fwrite(m->const_pool, sizeof(word_t), m->cp_size, snap_file);
    fwrite(&m->text_size, sizeof(uint32_t ), 1, snap_file);
    fwrite(m->text, sizeof(byte_t), m->text_size, snap_file);
    fwrite(&m->endian, sizeof(uint8_t), 1, snap_file);
    fwrite(&m->s, sizeof(stack), 1, snap_file);
    fwrite(&m->s.size, sizeof(uint32_t), 1, snap_file);
    fwrite(&m->s.capacity, sizeof(uint32_t ), 1, snap_file);
    fwrite(m->s.data, sizeof(word_t), m->s.capacity, snap_file);
    fwrite(&m->s.lv, sizeof(uint32_t ), 1, snap_file);

    fclose(snap_file);
}

ijvm* snap_init_ijvm(char* snapshot_path) {
    FILE *snap_file = fopen(snapshot_path, "rb");
    if (snap_file == NULL) {
        perror("Could not open snapshot snap_file \n");
        return NULL;
    }
    ijvm *m = (ijvm *) malloc(sizeof(ijvm));
    fread(&m->program_counter, sizeof(uint32_t), 1, snap_file);
    fread(&m->cp_size, sizeof(uint32_t), 1, snap_file);
    m->const_pool = (word_t *)malloc(m->cp_size * sizeof(word_t));
    fread(m->const_pool, sizeof(word_t), m->cp_size, snap_file);
    fread(&m->text_size, sizeof(uint32_t), 1, snap_file);
    m->text = (byte_t *)malloc(m->text_size * sizeof(byte_t));
    fread(m->text, sizeof(byte_t), m->text_size, snap_file);
    fread(&m->endian, sizeof(uint8_t), 1, snap_file);
    fread(&m->s, sizeof(stack), 1, snap_file);
    fread(&m->s.size, sizeof(uint32_t ), 1, snap_file);
    fread(&m->s.capacity, sizeof(uint32_t ), 1, snap_file);
    m->s.data = (word_t *) malloc(m->s.capacity * sizeof(word_t));
    fread(m->s.data, sizeof(word_t), m->s.capacity, snap_file);
    printf("TOS after: %d \n", tos(m));
    fread(&m->s.lv, sizeof(uint32_t ), 1, snap_file);
    m->running = 1;
    m->in = stdin;
    m->out = stdout;
    fclose(snap_file);

    printf("finished reading \n");
    return m;
}

void handle_sigint(int sig) {
    snapshot = true;
}

// see ijvm.h for descriptions of the below functions

ijvm* init_ijvm(char *binary_path, FILE* input , FILE* output) 
{
  // do not change these first three lines
  ijvm* m = (ijvm *) malloc(sizeof(ijvm));
  m->in = input;
  m->out = output;

  //initialize file
  m->s.size = 256;
  m->s.capacity = 1024;
  m->s.data = (word_t *)malloc(m->s.capacity * sizeof(word_t));
  m->s.lv = 0;

  m->capacity_heap = 1024;
  m->size_heap = 0;
  m->h = (arr *)malloc(m->capacity_heap * sizeof(arr));

  m->binary_file = fopen(binary_path, "rb");
  if (m->binary_file == NULL) {
      fprintf(stderr, "Could not open file.\n");
      destroy_ijvm(m);
      return NULL;
  }

  // initialize endian
  uint32_t magic_number;
  uint8_t mn_buffer[4];
  fread(mn_buffer, sizeof(byte_t), 4, m->binary_file);
  magic_number = read_uint32(mn_buffer);
  if(magic_number != MAGIC_NUMBER) {
    return NULL;
  }
  int reversed = 0x1DEADFAD;
  int straight = 0xADDFEA1D;
  if(magic_number == reversed) {
      m->endian = 0;
  } else if (magic_number == straight) {
      m->endian = 1;
  } else {
      return NULL;
  }

  uint8_t buffer[4];

  fread(buffer, sizeof(uint8_t), 4, m->binary_file);

  // initialize constant pool size
  fread(buffer, sizeof(uint8_t), 4, m->binary_file);
  m->cp_size = read_uint32(buffer);
  if (m->endian == 0) 
    swap_uint32(m->cp_size);

  // initialize constant pool
  m->const_pool = (word_t *)malloc((m->cp_size)/4 * sizeof(word_t));
  fread(m->const_pool, sizeof(word_t), (m->cp_size)/4, m->binary_file);

  // skip text origin
  fread(buffer, sizeof(byte_t), 4, m->binary_file);

  // initialize text_size 
  fread(buffer, sizeof(byte_t), 4, m->binary_file);
  m->text_size = read_uint32(buffer);  
  if (m->endian == 0) 
    swap_uint32(m->text_size);

  // initialize text
  m->text = (byte_t *)malloc(m->text_size * sizeof(byte_t));
  fread(m->text, sizeof(byte_t), m->text_size, m->binary_file);

  m->program_counter = 0;
  m->running = 1;

  signal(SIGINT, handle_sigint);
  return m;
}

void destroy_ijvm(ijvm* m)
{
    free(m->const_pool);
    free(m->text);
    free(m->s.data);
    free(m);
}

void destroy_stack(ijvm *m) {
    free(m->s.data);
}

byte_t *get_text(ijvm* m) 
{
  return m->text;
}

unsigned int get_text_size(ijvm* m) 
{ 
  return m->text_size;
}

word_t get_constant(ijvm* m, int i) 
{
  word_t constant = read_uint32(m->const_pool+i);
  return constant;
}

unsigned int get_program_counter(ijvm* m) 
{
  return m->program_counter;
}

word_t tos(ijvm* m) 
{
    int32_t top = m->s.data[m->s.size];
   return top;
}

bool finished(ijvm* m) 
{
  if (m->program_counter >= m->text_size) {
    return true;
  }
  if(m->running == 0) {
    return true;
  }
  return false;
}

word_t get_local_variable(ijvm* m, int i) 
{
  return m->s.data[m->s.lv+i];
}

void push(ijvm* m, word_t data)
{
  m->s.size++;
  if(m->s.size >= m->s.capacity) {
    uint32_t new_capacity = m->s.capacity * 2;
    m->s.data = (word_t *)realloc(m->s.data, new_capacity * sizeof(word_t));
    m->s.capacity = new_capacity;
  }
  m->s.data[m->s.size] = data;
}

word_t pop(ijvm *m)
{
  word_t value = m->s.data[m->s.size];
  m->s.size--;
  return value;
}

void step(ijvm* m) 
{
  byte_t instruction = get_instruction(m);
  m->program_counter++;

  int eof_cmp;
  int8_t value;
  word_t arg1;
  word_t arg2;
  word_t arg3;
  word_t result;
  int16_t short_arg;
  uint16_t wide_arg;
  byte_t byte_arg;
  uint16_t arg_num;
  uint16_t var_num;
  uint32_t method_address;
  uint32_t base;
  word_t ret_value;
  uint32_t call_pc;
  uint32_t call_lv;
  word_t *args;

  switch(instruction)
  {
    case OP_BIPUSH:
      value = (int8_t )m->text[get_program_counter(m)];
      m->program_counter++;
      push(m, value);
      break;

    case OP_DUP:
      result = m->s.data[m->s.size];
      push(m, result);
      break;

    case OP_IADD:
      arg1 = pop(m);
      arg2 = pop(m);
      result = arg1 + arg2;
      push(m, result);
      break;

    case OP_IAND:
      arg1 = pop(m);
      arg2 = pop(m);
      result = arg1 & arg2;
      push(m, result);
      break;

    case OP_IOR:
      arg1 = pop(m);
      arg2 = pop(m);
      result = arg1 | arg2;
      push(m, result);
      break;

    case OP_ISUB:
      arg1 = pop(m);
      arg2 = pop(m);
      result = arg2 - arg1;
      push(m, result);
      break;

    case OP_NOP:
      break;

    case OP_POP:
      pop(m);
      break;

    case OP_SWAP:
      arg1 = pop(m);
      arg2 = pop(m);
      push(m, arg1);
      push(m, arg2);
      break;

    case OP_ERR:
      fprintf(m->out, "ERR");
      m->running = 0;
      break;

    case OP_HALT:
      m->running = 0;
      break;

    case OP_IN:
      eof_cmp = fgetc(m->in);
      if (eof_cmp == EOF) {
        push(m, 0);
      }
      else {
        push(m, (word_t)eof_cmp);
      }
      break;

    case OP_OUT:
      arg1 = pop(m);
      fprintf(m->out, "%c", arg1);
      break;

    case OP_GOTO:
      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      m->program_counter += short_arg - 1;
      break;

    case OP_IFEQ:
      arg1 = pop(m);
      short_arg = read_int16(&m->text[get_program_counter(m)]);
      if (arg1 == 0) {
        m->program_counter += short_arg-1;
      } else {
        m->program_counter += 2;
      }
      break;

    case OP_IFLT:
      arg1 = pop(m);
      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      if (arg1 < 0) {
         m->program_counter += short_arg -1;
      } else {
        m->program_counter += 2;
      }
      break;

    case OP_IF_ICMPEQ:
      arg1 = pop(m);
      arg2 = pop(m);
      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      if (arg1 == arg2) {
         m->program_counter += short_arg -1;
      } else {
        m->program_counter += 2;
      }
      break;

    case OP_LDC_W:
      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      m->program_counter += 2;
      push(m, get_constant(m, short_arg));
      break;

    case OP_ILOAD:
      byte_arg = m->text[get_program_counter(m)];
      m->program_counter++;
      push(m, m->s.data[m->s.lv+byte_arg]);
      break;

    case OP_ISTORE:
      arg1 = pop(m);
      byte_arg = m->text[get_program_counter(m)];
      m->program_counter++;
      m->s.data[m->s.lv+byte_arg] = arg1;
      break;

    case OP_IINC:
      byte_arg = m->text[get_program_counter(m)];
      m->program_counter++;
      value = m->text[get_program_counter(m)];
      m->program_counter++;
      m->s.data[m->s.lv+byte_arg] += value;
      break;

    case OP_WIDE:
      instruction = m->text[get_program_counter(m)];
      m->program_counter++;
      switch (instruction)
      {
        case OP_ILOAD:
          wide_arg = (uint16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
          m->program_counter += 2;
          push(m, m->s.data[m->s.lv+wide_arg]);
          break;

        case OP_ISTORE:
          arg1 = pop(m);
          wide_arg = (uint16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
          m->program_counter += 2;
          m->s.data[m->s.lv+wide_arg] = arg1;
          break;

        case OP_IINC:
          wide_arg = (uint16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
          m->program_counter += 2;
          value = m->text[get_program_counter(m)];
          m->program_counter++;
          m->s.data[m->s.lv+wide_arg] += value;
          break;
      }
      break;

    case OP_INVOKEVIRTUAL:
      call_pc = m->program_counter;
      call_lv = m->s.lv;

      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      method_address = get_constant(m, short_arg);

      arg_num = (uint16_t)(m->text[method_address] << 8 | m->text[method_address+1]);
      var_num = (uint16_t)(m->text[method_address+2] << 8 | m->text[method_address+3]);
      for (uint32_t i=0; i<var_num; i++)  {
        push(m, 0);
      }

      m->program_counter = method_address + 4;
      m->s.lv = m->s.size - arg_num - var_num + 1;
      m->s.size = m->s.lv + arg_num + var_num;

      push(m, call_pc);
      m->s.data[m->s.lv] = m->s.size;
      push(m, call_lv);
      break;

    case OP_IRETURN:
      ret_value = pop(m);
      m->program_counter = m->s.data[m->s.data[m->s.lv]] + 2;
      base = m->s.lv;
      m->s.lv = m->s.data[m->s.data[m->s.lv]+1];
      m->s.size = base;
      m->s.data[m->s.size] = ret_value;
      break;

    case OP_TAILCALL:
      short_arg = (int16_t)(m->text[get_program_counter(m)] << 8 | m->text[get_program_counter(m) + 1]);
      method_address = get_constant(m, short_arg);

      arg_num = (uint16_t)(m->text[method_address] << 8 | m->text[method_address + 1]);
      var_num = (uint16_t)(m->text[method_address + 2] << 8 | m->text[method_address + 3]);

      args = (word_t *) malloc(arg_num * sizeof(word_t));
      for (uint32_t i = 0; i < arg_num; i++) {
          args[i] = pop(m);
      }

      arg1 = m->s.data[m->s.data[m->s.lv]]; // old pc
      arg2= m->s.data[m->s.data[m->s.lv]+1]; // old lv
      m->s.size = m->s.lv;

      for (int i = arg_num-2; i >= 0; i--) {
          push(m, args[i]);
      }
      free(args);

      for (int i=0; i<var_num; i++)  {
          push(m, 0);
      }

      m->program_counter = method_address + 4;
      push(m, arg1);
      push(m, arg2);
      m->s.data[m->s.lv] = m->s.size-1;
      break;


    case OP_NEWARRAY:
        arg1 = pop(m);
        if(m->size_heap >= m->capacity_heap)
        {
            m->capacity_heap =  2*m->capacity_heap;
            m->h = (arr* )realloc(m->h, m->capacity_heap * sizeof(arr));
        }
        m->h[m->size_heap].values = (word_t *)calloc(arg1, sizeof(word_t));
          m->h[m->size_heap].size = arg1;
        push(m, m->size_heap);
        m->size_heap++;
        break;

    case OP_IALOAD:
        arg1 = pop(m); //arrayref
        arg2 = pop(m);  //index
        if(arg1 >= m->size_heap) {
            perror("Out of bounds");
            exit(1);
        }
          if(arg2 >= m->h[arg1].size) {
              perror("Out of bounds");
              exit(1);
          }
        push(m, m->h[arg1].values[arg2]);
        break;

    case OP_IASTORE:
        arg1 = pop(m); //arrayref
        arg2 = pop(m); //index
        arg3 = pop(m); //value
          if(arg1 > m->size_heap) {
              perror("Out of bounds");
              exit(1);
          }
        if(arg2 > m->h[arg1].size) {
            perror("Out of bounds");
            exit(1);
        }
        m->h[arg1].values[arg2] = arg3;
        break;

    default:
      break;
  }
}

byte_t get_instruction(ijvm* m) 
{ 
  return get_text(m)[get_program_counter(m)]; 
}

ijvm* init_ijvm_std(char *binary_path) 
{
  return init_ijvm(binary_path, stdin, stdout);
}

void run(ijvm* m)
{
    while (!finished(m))
    {
        if(snapshot) {
            take_snapshot(m);
            snapshot = false;
            exit(1);
        }
        else {
            step(m);
        }
    }
}

// Below: methods needed by bonus assignments, see ijvm.h
// You can leave these unimplemented if you are not doing these bonus 
// assignments.

int get_call_stack_size(ijvm* m) 
{
    int size = 0;
    for(uint32_t i = m->s.lv; i < m->s.size; i++) {
        size++;
    }
    return size;
}


// Checks if reference is a freed heap array. Note that this assumes that 
// 
bool is_heap_freed(ijvm* m, word_t reference) 
{
   // TODO: implement me if doing garbage collection bonus
   return 0;
}

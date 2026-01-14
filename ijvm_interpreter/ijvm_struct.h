
#ifndef IJVM_STRUCT_H
#define IJVM_STRUCT_H

#include <stdio.h>  /* contains type FILE * */

#include "ijvm_types.h"
#include <signal.h>
#include <stdbool.h>
/**
 * All the state of your IJVM machine goes in this struct!
 **/

typedef struct ARR {
    word_t *values;
    word_t size;
} arr;

typedef struct STACK {
  word_t *data;
  uint32_t size;
  uint32_t capacity;
  uint32_t lv;
} stack;

typedef struct IJVM {
    // do not changes these two variables
    FILE *in;   // use fgetc(ijvm->in) to get a character from in.
                // This will return EOF if no char is available.
    FILE *out;  // use for example fprintf(ijvm->out, "%c", value); to print value to out

  // your variables go here

  FILE *binary_file;
  uint8_t endian;
  uint32_t program_counter;
  uint32_t cp_size;
  uint32_t text_size;
  uint8_t running;
  byte_t *text;
  word_t *const_pool;
  stack s;

  arr* h;
  word_t size_heap;
  word_t capacity_heap;
} ijvm;

#endif

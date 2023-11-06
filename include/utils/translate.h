#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void hex_to_str(uint8_t *num, char *str, int bytes);
void str_to_hex(char *str, uint8_t *num, int bytes);
int unescape(char *msg, char *end);

#endif

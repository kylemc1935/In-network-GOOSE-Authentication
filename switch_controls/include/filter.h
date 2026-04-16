#ifndef FILTER_H
#define FILTER_H

#include <stdint.h>
#include <stdio.h>

// simple filter for checking if GOOSE
int is_goose(const unsigned char *pkt, unsigned int len);

#endif

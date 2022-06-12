#pragma once

#define __BSS(x)__attribute__ ((section(".dram")))
#define INLINE inline

#include "LPC177x_8x.h"
#include "lpc_types.h"

#include <stdint.h>

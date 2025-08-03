#ifndef SNARK_EXPORT_H
#define SNARK_EXPORT_H

#include <stdint.h>

// Export SNARK data to JSON format
int export_snark_json(const char *filename, const uint8_t *msg, size_t msg_len);

#endif

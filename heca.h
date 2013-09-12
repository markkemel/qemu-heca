#ifndef QEMU_HECA_H_
#define QEMU_HECA_H_

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <wordexp.h>
#include "memory.h"

void heca_cmd_slave_init(QemuOpts *opts);
void hecamr_cmd_add(QemuOpts *opts);
void hecaproc_cmd_add(QemuOpts *opts);
void heca_cmd_init(QemuOpts *opts);
void heca_check_params(void);
void heca_check_mrs(uint64_t ram_size);
void heca_init(void* ram_ptr, uint64_t ram_size);
void heca_migrate_dest_init(const char* dest_ip, const char* source_ip); 
void heca_migrate_src_init(const char* dest_ip, int precopy_time);
void heca_set_post_copy_phase(void);
bool heca_is_mig_timer_expired(void);
bool heca_is_master(void);
bool heca_is_enabled(void);
int heca_unmap_dirty_bitmap(uint8_t *bitmap, uint32_t bitmap_size);
bool heca_is_pre_copy_phase(void);

#endif /* QEMU_HECA_H_ */


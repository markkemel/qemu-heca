#include <libheca.h>
#include "qemu/timer.h"
#include "exec/memory.h"
#include "sysemu/sysemu.h"
#include "heca.h"

#ifdef DEBUG_HECA
#define DPRINTF(fmt, ...) \
    do { printf("heca-all: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_HECA_STUB
int heca_gdb_pause = 1;
#define heca_gdb_stub() \
    do { \
        fprintf(stderr, "\n"); \
        fprintf(stderr, "Execution paused - use GDB to continue:\n"); \
        fprintf(stderr, "   gdb -p %d\n", getpid()); \
        fprintf(stderr, "   gdb> set variable heca_gdb_pause = 0\n"); \
        fprintf(stderr, "   gdb> continue\n"); \
        while (heca_gdb_pause); \
        fprintf(stderr, "Normal execution has resumed\n"); \
    } while (0)
#else
#define heca_gdb_stub() \
    do { } while (0)
#endif

#define MAX_HPROCS 512
#define MAX_MRS 512

typedef struct Heca {
    bool is_enabled;
    bool is_master;
    uint8_t hspace_id;
    int rdma_fd;
    int rdma_port;
    int tcp_sync_port;
    uint32_t hproc_count;
    uint32_t mr_count;
    struct hecaioc_hproc hproc_array[MAX_HPROCS];
    struct hecaioc_hmr mr_array[MAX_MRS];
    uint32_t local_hproc_id;
    QEMUTimer *migration_timer;
    bool is_timer_expired;
    bool is_iterative_phase;
    struct sockaddr_in master_addr;
} Heca;

Heca heca;

void *heca_get_system_ram_ptr(void);
uint64_t heca_get_system_ram_size(void);
void heca_start_mig_timer(uint64_t timeout);
int heca_unmap_memory(void *addr, size_t size);
void heca_cmd_err(const char *msg, int *param, bool kill);
static void print_data_structures(void);
static const char *ip_from_uri(const char *uri);
static void heca_config(void);

bool heca_is_master(void)
{
    return heca.is_master;
}

bool heca_is_enabled(void)
{
    return heca.is_enabled;
}

void hecamr_cmd_add(QemuOpts *opts)
{
    char hprocs[MAX_HPROC_IDS*10];
    char *hpr;
    const char* hprocstmp;
    int mrstrsz = sizeof(struct hecaioc_hmr), pgsz;
    int i = 0;
    struct hecaioc_hmr *newhmr;
    bool finished = false;

    if (heca.mr_count >= MAX_MRS)
        heca_cmd_err("Too many mr's", NULL, true);
    if (!heca.is_master)
        heca_cmd_err("-hecamr should follow -heca mode=master", NULL, true);
    newhmr = g_malloc0(sizeof(struct hecaioc_hmr));
    assert(newhmr);
    newhmr->hspace_id = heca.hspace_id;
    newhmr->hmr_id = heca.mr_count + 1;
    newhmr->addr = (void *) qemu_opt_get_number(opts, "start", -1);
    newhmr->sz = qemu_opt_get_size(opts, "size", -1);
    hprocstmp = qemu_opt_get(opts, "hprocids");
    if (newhmr->addr == (void *) -1 || newhmr->sz == -1 || !hprocstmp) {
        heca_cmd_err("Specify start, size, hprocids in -hecamr", NULL, false);
        goto done;
    }
    if (!newhmr->sz || newhmr->sz & (TARGET_PAGE_SIZE - 1)) {
        pgsz = TARGET_PAGE_SIZE;
        heca_cmd_err("Memory size has to be a multiple of: ", &pgsz, false);
        goto done;
    }
    strcpy(hprocs, hprocstmp);
    memset(newhmr->hproc_ids, 0, sizeof(newhmr->hproc_ids[0]) * MAX_HPROC_IDS);
    hpr = strtok(hprocs, ":");
    while (!hpr) {
        if (i == MAX_HPROC_IDS) {
            heca_cmd_err("Too many hprocs for memory region", NULL, false);
            goto done;
        }
        newhmr->hproc_ids[i] = atoi(hpr);
        i++;
        hpr = strtok(NULL, ":");
    }
    i = heca.mr_count; 
    memcpy(&heca.mr_array[i], newhmr, mrstrsz);
    heca.mr_count++;

    DPRINTF("mr id: %d\n", newhmr->hmr_id);
    DPRINTF("mr addr: %lld\n", (long long int)newhmr->addr);
    DPRINTF("mr sz: %lu\n", newhmr->sz);
    DPRINTF("mr hprocids: %s\n", hprocs);
    finished = true;
done:
    g_free(newhmr);
    if (!finished)
        exit(1);
}

void hecaproc_cmd_add(QemuOpts *opts)
{
    const char* ip;
    int rdma_port, mng_port, i;
    int hpstrsz = sizeof(struct hecaioc_hproc);
    bool finished = false;

    if (heca.hproc_count >= MAX_HPROCS)
        heca_cmd_err("Too many hprocs", NULL, true);
    if (!heca.is_master)
        heca_cmd_err("-hecaproc should follow -heca mode=master", NULL, true);
    struct hecaioc_hproc *newhproc = g_malloc0(sizeof(struct hecaioc_hproc));
    newhproc->hspace_id = heca.hspace_id;
    newhproc->hproc_id = qemu_opt_get_number(opts, "hprocid", -1);
    ip = qemu_opt_get(opts, "ip");
    rdma_port = qemu_opt_get_number(opts, "rdma_port", -1);
    mng_port = qemu_opt_get_number(opts, "mng_port", -1);
    if (rdma_port == -1 || mng_port == -1 || newhproc->hproc_id == -1 || !ip) {
        heca_cmd_err("Specify hprocid, ip, ports for -hecaproc", NULL, false);
        goto done;
    }
    if ((newhproc->hproc_id & 0xFFFF) != newhproc->hproc_id) {
        heca_cmd_err("Invalid hprocid for -hproc", NULL, false);
        goto done;
    }
    newhproc->remote.sin_addr.s_addr = inet_addr(ip);
    newhproc->remote.sin_port = htons(rdma_port);
    i = heca.hproc_count;
    memcpy(&heca.hproc_array[i], newhproc, hpstrsz);
    heca.hproc_count++;
    if (newhproc->remote.sin_addr.s_addr == INADDR_NONE) {
        heca_cmd_err("Invalid IP address", NULL, false);
        goto done;
    }
    DPRINTF("hproc id is: %d\n", newhproc->hproc_id);
    DPRINTF("ip is: %s\n", ip);
    DPRINTF("rdma port is: %d\n", rdma_port);
    DPRINTF("mng port is: %d\n", mng_port);
    finished = true;
done:
    g_free(newhproc);
    if (!finished)
        exit(1);
}

void heca_cmd_slave_init(QemuOpts *opts)
{
    int rdma_port, mng_port;
    const char* ip;

    heca.local_hproc_id = qemu_opt_get_number(opts, "hprocid", -1);
    rdma_port = qemu_opt_get_number(opts, "rdma_port", -1);
    mng_port = qemu_opt_get_number(opts, "mng_port", -1);
    ip = qemu_opt_get(opts, "masterip");

    if (rdma_port == -1 || mng_port == -1|| heca.local_hproc_id == -1 || !ip)
        heca_cmd_err("hprocid, ip, ports are implied for slave", NULL, true);
    bzero((char*) &heca.master_addr, sizeof(heca.master_addr));
    heca.master_addr.sin_family = AF_INET;
    heca.master_addr.sin_port = htons(mng_port);
    heca.master_addr.sin_addr.s_addr = inet_addr(ip);
    if (heca.master_addr.sin_addr.s_addr == INADDR_NONE)
        heca_cmd_err("Invalid IP address", NULL, true);
    DPRINTF("hspaceid = %d\n", heca.hspace_id);
    DPRINTF("hprocid = %d\n", heca.local_hproc_id);
    DPRINTF("ip : %s\n",ip);
    DPRINTF("rdma port: %d\n", rdma_port);
    DPRINTF("tcp port: %d\n", mng_port);
}

void heca_cmd_init(QemuOpts *opts)
{
    const char* mode;
    
    heca.is_enabled = true;
    heca.hspace_id = qemu_opt_get_number(opts, "hspaceid", -1);
    mode = qemu_opt_get(opts, "mode");
    if (mode && strcmp(mode, "master") == 0) {
        heca.is_master = true;
        heca.local_hproc_id = 1; /* Always 1 for master */
        heca_gdb_stub();
    }
    else if (mode && strcmp(mode, "slave") == 0) {
        heca.is_master = false;
        heca_gdb_stub();
        heca_cmd_slave_init(opts);
    }
    else
        heca_cmd_err("Mode should only have values master|slave", NULL, true);
    if (heca.hspace_id == (uint8_t) -1) /* Validate parameters */
        heca_cmd_err("hspaceid is implied for -heca parameter", NULL, true);
}

void heca_check_params(void)
{
    if (heca.is_master)
        if (heca.mr_count == 0 || heca.hproc_count == 0)
            heca_cmd_err("Specify hmrs and hprocs for master!", NULL, true);
}

/* Check MRs' memory overlapping
   Check if overall MRs' size exceed vmmem*/
void heca_check_mrs(uint64_t ram_size)
{
    int i, j;
    size_t starti, endi, startj, endj, allmem = 0;

    for (i=0; i < heca.mr_count; i++) {
        starti = (size_t) heca.mr_array[i].addr;
        endi = (size_t)heca.mr_array[i].addr + heca.mr_array[i].sz - 1;
        for (j=i+1; j < heca.mr_count; j++) {
            startj = (size_t)heca.mr_array[j].addr;
            endj = (size_t)heca.mr_array[j].addr + heca.mr_array[j].sz - 1;
            if (endi >= startj && starti <= endj)
                heca_cmd_err("hmr virtual addresses overlap", NULL, true);
        }
        allmem+=heca.mr_array[i].sz;
    }
    if (allmem > ram_size)
        heca_cmd_err("overall hmr sizes exceed machine memory", NULL, true);
}

void heca_cmd_err(const char *msg, int *param, bool kill)
{
    if (param == NULL)
        fprintf(stderr, "[HECA ERROR]: %s\n", msg);
    else
        fprintf(stderr, "[HECA ERROR]: %s%d\n", msg, *param);
    if(kill)
        exit(1);
}

void heca_migrate_dest_init(const char* dest_ip, const char* source_ip)
{
    heca_config();
    heca.is_enabled = true;
    heca.hspace_id = 1;         /* only need 1 for live migration (LM) */
    heca.local_hproc_id = 1;    /* master node is 1 */
    heca.hproc_count = 2;       /* only master and slave required for LM */
    heca.mr_count = 1;          /* only need 1 memory region for LM */

    struct hecaioc_hproc dst_hproc = {
        .hspace_id = 1,
        .hproc_id = 1,
        .remote = {
            .sin_addr.s_addr = inet_addr(dest_ip),
            .sin_port = htons(heca.rdma_port)
        }
    };
    struct hecaioc_hproc src_hproc = {
        .hspace_id = 1,
        .hproc_id = 2,
        .remote = {
            .sin_addr.s_addr = inet_addr(source_ip),
            .sin_port = htons(heca.rdma_port)
        }
    };

    heca.hproc_array[0] = dst_hproc;
    heca.hproc_array[1] = src_hproc;

    struct hecaioc_hmr mr = {
        .hspace_id = 1,
        .hmr_id = 1,
        .hproc_ids = { 2, 0 },
        .flags = UD_COPY_ON_ACCESS
    };
    heca.mr_array[0] = mr;

    void *ram_ptr = heca_get_system_ram_ptr();
    if (!ram_ptr) {
        DPRINTF("Error getting ram_ptr to system memory\n");
        exit(1);
    }
    uint64_t ram_sz = heca_get_system_ram_size();

    heca.mr_array[0].addr = ram_ptr; /*only one memory region required for LM*/
    heca.mr_array[0].sz = ram_sz;

    DPRINTF("initializing heca master\n");

    /* print_data_structures(); */
    heca.rdma_fd = heca_master_open(heca.hproc_count, 
            heca.hproc_array, heca.mr_count, heca.mr_array);

    if (heca.rdma_fd < 0) {
        DPRINTF("Error initializing master node\n");
        exit(1);
    }

    DPRINTF("Heca master node is ready..\n");
    /* hspace_cleanup(fd); */
}

void heca_migrate_src_init(const char *uri, int precopy_time)
{
    heca_config();

    heca.is_enabled = true;
    heca.hspace_id = 1;         /* only need 1 for live migration (LM) */
    heca.local_hproc_id = 2;    /* slave node */
    heca.hproc_count = 2;       /* only master and slave required for LM */

    const char *dest_ip = ip_from_uri(uri);
    bzero((char*) &heca.master_addr, sizeof(heca.master_addr));
    heca.master_addr.sin_family = AF_INET;
    heca.master_addr.sin_port = htons(heca.tcp_sync_port);
    heca.master_addr.sin_addr.s_addr = inet_addr(dest_ip);

    heca_start_mig_timer(precopy_time);

    void *ram_ptr = heca_get_system_ram_ptr();
    uint64_t ram_size = heca_get_system_ram_size();
    if (!ram_ptr) {
        DPRINTF("Error getting ram pointer\n");
        exit(1);
    }

    DPRINTF("initializing heca slave node ...\n");
    
    heca.rdma_fd = heca_client_open(ram_ptr, ram_size, 
            heca.local_hproc_id, &heca.master_addr);

    if (heca.rdma_fd < 0 ) {
        DPRINTF("Error initializing slave node\n");
        exit(1);
    }

    DPRINTF("Heca slave node is ready..\n");
    /* hspace_cleanup(fd); */
}

static const char *ip_from_uri(const char *uri) 
{
    char char_array_uri[256];

    char_array_uri[sizeof(char_array_uri) - 1] = 0;
    strncpy(char_array_uri, uri, sizeof(char_array_uri) - 1);
    
    /* ip points to uri protocol, e.g. 'tcp' */
    char* ip = strtok(char_array_uri, ":");
    /* ip now points to ip address */
    ip = strtok(NULL, ":");
    return (const char*) ip;
}

static void heca_config(void)
{
    /* read file .heca_config. Ideally, all configuration 
       would be contained here. */
    wordexp_t result;
    wordexp("~/.heca_config", &result, 0);
    const char* heca_conf_path = result.we_wordv[0];

    FILE *conf_file = fopen(heca_conf_path, "r");
    if (conf_file == NULL) {
        /* use default port values */
        heca.rdma_port = 4444;
        heca.tcp_sync_port = 4445;
    }
    else {
        if (fscanf(conf_file, "RDMA_PORT=%d", &heca.rdma_port) < 1) {
            fprintf(stderr, "Couldn't read RDMA_PORT - defaulting to 4444\n");
            heca.rdma_port = 4444;
        }
        if (fscanf(conf_file, "TCP_SYNC_PORT=%d", &heca.tcp_sync_port) < 1) {
            fprintf(stderr, "Couldn't read TCP_SYNC_PORT defaulting to 4445\n");
            heca.tcp_sync_port = 4445;
        }
    }
}

static inline int heca_assign_master_mem(void *ram_ptr, uint64_t ram_size)
{
    int i;
    void *pos = ram_ptr;

    for (i = 0; i < heca.mr_count; i++) {
        if (pos > ram_ptr + ram_size)
            return -1;
        heca.mr_array[i].addr = pos;
        pos += heca.mr_array[i].sz;
    }

    return 0;
}

static void print_data_structures(void)
{
    int i, j;

    printf("hproc_array:\n");
    for (i = 0; i < heca.hproc_count; i++) {
        printf("{ .hspace_id = %d, .hproc_id = %d, .ip = %s, .port = %d}\n", 
            heca.hproc_array[i].hspace_id, heca.hproc_array[i].hproc_id, 
            inet_ntoa(heca.hproc_array[i].remote.sin_addr),
            ntohs(heca.hproc_array[i].remote.sin_port));
    }
    printf("mr_array:\n");
    for (i = 0; i < heca.mr_count; i++) {
        printf("{ .hspace_id = %d, .hmr_id = %d, .addr = %ld, ",
                heca.mr_array[i].hspace_id, heca.mr_array[i].hmr_id, 
                (unsigned long) heca.mr_array[i].addr); 
        printf(".sz = %lld, .flags = %d, .hproc_ids = { ",
                (long long) heca.mr_array[i].sz, heca.mr_array[i].flags);
        j = 0;
        while(heca.mr_array[i].hproc_ids[j] != 0 && j < MAX_HPROC_IDS) {
            printf("%d, ", heca.mr_array[i].hproc_ids[j]);
            j++;
        }
        printf("0 } }\n");
    }
}

static inline MemoryRegion *heca_get_system_mr(void)
{
    RAMBlock *block;
    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        if (strncmp(block->idstr, "pc.ram", strlen(block->idstr)) == 0)
            return block->mr; 
    }
    return NULL;
}

void *heca_get_system_ram_ptr(void)
{
    MemoryRegion *sys_mr = heca_get_system_mr();
    if (sys_mr)
        return memory_region_get_ram_ptr(sys_mr);
    return NULL;
}

uint64_t heca_get_system_ram_size(void)
{
    MemoryRegion *sys_mr = heca_get_system_mr();
    if (sys_mr)
        return memory_region_size(sys_mr);
    return 0;
}

static void * touch_all_ram_worker(void *arg)
{
    ram_addr_t block_addr, block_end, addr;
    unsigned long long block_length;

    RAMBlock *block;
    unsigned long buf;
    
    DPRINTF("Starting to pull all pages to local node.\n");

    QTAILQ_FOREACH(block, &ram_list.blocks, next) {
        if (strncmp(block->idstr,"pc.ram",strlen(block->idstr)) == 0)
        {
            block_addr = block->mr->addr;
            block_length = block->length;
            block_end = block_addr + block_length; 
            addr = block_addr;
            while(addr < block_end) {
                addr += TARGET_PAGE_SIZE;
                cpu_physical_memory_read(addr, &buf, sizeof(buf));
            }
        }
    }

    DPRINTF("Finished reading ram, please terminate the source node.\n");
    /* TODO: Send a message to the source to self terminate */

    pthread_exit(NULL);
}

static void heca_change_state_handler(void *opaque, int running,
        RunState state)
{
    static int has_run;
    pthread_t t;

    if (running && !has_run++)
        pthread_create(&t, NULL, touch_all_ram_worker, NULL);
}

int heca_unmap_memory(void* addr, size_t size)
{
    int ret = 0;

    // create unmap object for dirty range and unmap it

    struct hecaioc_ps ps_data;
    ps_data.pid = 0;
    ps_data.addr = addr;
    ps_data.sz = size;


    /* FIXME - externd linux-heca and libheca */
    ret = ioctl(heca.rdma_fd, HECAIOC_PS_UNMAP, &ps_data);
    if (ret)
        return -1;
    else
        return ret;
    return -1;
}

static void mig_timer_expired(void *opaque)
{
    heca.is_timer_expired = true;
    qemu_del_timer(heca.migration_timer);
}

void heca_start_mig_timer(uint64_t timeout) 
{
    heca.migration_timer = qemu_new_timer_ms(rt_clock, mig_timer_expired, NULL);
    qemu_mod_timer(heca.migration_timer, qemu_get_clock_ms(rt_clock) + timeout);
}

bool heca_is_mig_timer_expired(void)
{
    return heca.is_timer_expired;
}

void heca_set_post_copy_phase(void)
{
    heca.is_iterative_phase = false;
}

bool heca_is_pre_copy_phase(void)
{
    return heca.is_iterative_phase;
}

int heca_unmap_dirty_bitmap(uint8_t *bitmap, uint32_t bitmap_size)
{
    unsigned long host_ram;
    int i, ret = 0;
    void * unmap_addr = NULL;

    host_ram = (unsigned long) heca_get_system_ram_ptr();
 
    size_t unmap_size = 0;
    unsigned long unmap_offset = -1;
    int count = 0;

    for (i = 0; i < bitmap_size; i++) {
        if (bitmap[i] & 0x08) { 
            /* page is dirty, flag start of dirty range */
            count ++;
            if (unmap_offset == -1) 
                unmap_offset = i * TARGET_PAGE_SIZE;
            unmap_size += TARGET_PAGE_SIZE;
        } else if (unmap_size > 0) {
            /* end of dirty range */
            unmap_addr = (void*) (host_ram + unmap_offset);
            ret = heca_unmap_memory(unmap_addr, unmap_size);
            if (ret < 0) {
                return ret;
            }
            /* reset */
            unmap_offset = -1;
            unmap_size = 0;
        }
    }
    if (unmap_size > 0) {
        /* Last page was dirty but we have finished iterating over bitmap */
        unmap_addr = (void*) (host_ram + unmap_offset);
        ret = heca_unmap_memory(unmap_addr, unmap_size);
        if (ret < 0) {
            return ret;
        }
    }
    qemu_add_vm_change_state_handler(heca_change_state_handler, NULL);
    return ret;
}

void heca_init(void* ram_ptr, uint64_t ram_size)
{
    if (heca.is_master) {
        bool debug = true;
        if (debug) 
            print_data_structures();

        heca_assign_master_mem(ram_ptr, ram_size);

        /* init heca */
        heca.rdma_fd = heca_master_open(heca.hproc_count, 
                heca.hproc_array, heca.mr_count, heca.mr_array);
    } else {
        heca.rdma_fd = heca_client_open(ram_ptr, ram_size, 
                heca.local_hproc_id, &heca.master_addr);
    }

    if (heca.rdma_fd < 0) {
        DPRINTF("Error initializing master node\n");
        exit(1);
    }

    DPRINTF("Heca is ready...\n");
}


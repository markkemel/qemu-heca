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

void *heca_get_system_ram_ptr(void);
uint64_t heca_get_system_ram_size(void);
void heca_start_mig_timer(uint64_t timeout);
int heca_unmap_memory(void *addr, size_t size);
void parse_heca_master_commandline(const char* optarg);
void parse_heca_client_commandline(const char* optarg);

typedef struct Heca {
    bool is_enabled;
    bool is_master;
    uint8_t hspace_id;
    int rdma_fd;
    int rdma_port;
    int tcp_sync_port;
    uint32_t hproc_count;
    uint32_t mr_count;
    struct hecaioc_hproc *hproc_array;
    struct hecaioc_hmr *mr_array;
    uint32_t local_hproc_id;
    QEMUTimer *migration_timer;
    bool is_timer_expired;
    bool is_iterative_phase;
    struct sockaddr_in master_addr;
} Heca;

Heca heca;

bool heca_is_master(void)
{
    return heca.is_master;
}

bool heca_is_enabled(void)
{
    return heca.is_enabled;
}

static void print_data_structures(void);
static const char* ip_from_uri(const char* uri);
static void heca_config(void);

/* static helper functions for parsing commandline */
static void get_param(char *target, const char *name, int size, 
    const char *optarg)
{
    if (get_param_value(target, size, name, optarg) == 0) {
        fprintf(stderr, "Could not get parameter value");
        exit(1);
    }
}

static uint32_t get_param_int(const char *name, const char *optarg)
{
    char target[128];
    uint32_t result = 0;

    get_param(target, name, 128, optarg);
    result = strtoull(target, NULL, 10); 
    if (result <= 0 || (result & 0xFFFF) != result) {
        printf("error?\n");
        fprintf(stderr, "Could not get parameter value");
        exit(1);
    }
    return result;
}

/* setup data for heca_init to setup master and slave nodes */
void parse_heca_master_commandline(const char* optarg)
{
    GSList* hproc_list = NULL;
    GSList* mr_list = NULL;

    char nodeinfo_option[128];

    /* hspace general info */
    heca.hspace_id = get_param_int("hspaceid", optarg);
    DPRINTF("hspace_id = %d\n", heca.hspace_id);
    heca.local_hproc_id = 1; // always 1 for master
    DPRINTF("local_hproc_id = %d\n", heca.local_hproc_id);

    /* per-hproc info: id, ip, port */
    get_param(nodeinfo_option, "vminfo", sizeof(nodeinfo_option), optarg);
    const char *p = nodeinfo_option;
    char h_buf[500];
    char l_buf[500];
    const char *q;
    uint32_t i;
    uint32_t tcp_port;

    while (*p != '\0') {
        struct hecaioc_hproc *next_hproc = g_malloc0(sizeof(struct hecaioc_hproc));
        
        next_hproc->hspace_id = heca.hspace_id;

        p = get_opt_name(h_buf, sizeof(h_buf), p, '#');
        p++;
        q = get_opt_name(l_buf, sizeof(l_buf), h_buf, ':');
        q++;

        next_hproc->hproc_id = strtoull(l_buf, NULL, 10);
        if ((next_hproc->hproc_id & 0xFFFF) != next_hproc->hproc_id) {
            fprintf(stderr, "[HECA] Invalid hproc_id: %d\n",
                    (int)next_hproc->hproc_id);
            exit(1);
        }
        DPRINTF("hproc id is: %d\n", next_hproc->hproc_id);

        // Parse node IP
        q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
        q++;
        next_hproc->remote.sin_addr.s_addr = inet_addr(l_buf);
        DPRINTF("ip is: %s\n", l_buf);

        // Parse rdma port
        q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
        q++;
        next_hproc->remote.sin_port = htons(strtoull(l_buf, NULL, 10));
        DPRINTF("port is: %s\n", l_buf);

        // Parse tcp port
        q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
        q++;
        tcp_port = strtoull(l_buf, NULL, 10);
        if (tcp_port) /* FIXME: remove tcp_port - not needed */
            DPRINTF("tcp port is (not passed to libheca): %d\n", tcp_port);

        hproc_list = g_slist_append(hproc_list, next_hproc);
        heca.hproc_count++;
    }

    // Now, we setup the hproc_array with the hprocs created above 
    heca.hproc_array = calloc(heca.hproc_count, sizeof(struct hecaioc_hproc));
    struct hecaioc_hproc *hproc_ptr;
    for (i = 0; i < heca.hproc_count; i++) {
        hproc_ptr = g_slist_nth_data(hproc_list, i);
        memcpy(&heca.hproc_array[i], hproc_ptr, sizeof(struct hecaioc_hproc));
    }
    g_slist_free(hproc_list);

    /* mr info: sizes, owners */
    get_param(nodeinfo_option, "mr", sizeof(nodeinfo_option), optarg);
    p = nodeinfo_option;

    while (*p != '\0') {
        struct hecaioc_hmr *next_mr = g_malloc0(sizeof(struct hecaioc_hmr));

        p = get_opt_name(h_buf, sizeof(h_buf), p, '#');
        p++;
        q = h_buf;

        // Set hspace id
        next_mr->hspace_id = heca.hspace_id;

        // TODO: code to set id
        //next_mr->id = 1;

        // get memory region id
        q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
        q++;
        next_mr->hmr_id = strtoull(l_buf, NULL, 10);
        DPRINTF("mr id: %lld\n", (long long int)next_mr->addr);

        // get memory size
        q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
        q++;
        next_mr->sz = parse_size_string(l_buf);
        DPRINTF("mr sz: %lu\n", next_mr->sz);

        // check for correct memory size
        if (next_mr->sz == 0 || next_mr->sz % TARGET_PAGE_SIZE != 0) {
            fprintf(stderr, "HECA: Wrong mem size. \n \
                It has to be a multiple of %d\n", (int)TARGET_PAGE_SIZE);
            exit(1);
        }

        // get all hprocs for this memory region
        memset(next_mr->hproc_ids, 0, sizeof(next_mr->hproc_ids[0]) * MAX_HPROC_IDS);

        for (i = 0; *q != '\0'; i++) {
            if (i == MAX_HPROC_IDS) {
                fprintf(stderr, "HECA: Too many hprocs for memory region\n");
                exit(1);
            }

            q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
            if (strlen(q))
                q++;
            next_mr->hproc_ids[i] = strtoull(l_buf, NULL, 10);
            DPRINTF("adding mr owner: %d\n", next_mr->hproc_ids[i]);
        }

        // Set array of hprocs for each unmap region
        mr_list = g_slist_append(mr_list, next_mr);
        heca.mr_count++;
    }

    // Now, we setup the mr_array with the unmap_data structs created above
    heca.mr_array = calloc(heca.mr_count, sizeof(struct hecaioc_hmr));
    for (i = 0; i < heca.mr_count; i++) {
        memcpy(&heca.mr_array[i], g_slist_nth_data(mr_list, i),
                sizeof(struct hecaioc_hmr));
    }

    g_slist_free(mr_list);
}

void parse_heca_client_commandline(const char* optarg) 
{
    printf("parse_heca_client_commandline\n");
    heca.hspace_id = get_param_int("hspaceid", optarg);
    printf("hspace_id = %d\n", heca.hspace_id);

    DPRINTF("hspace_id = %d\n", heca.hspace_id);

    heca.local_hproc_id = get_param_int("vmid", optarg);
    DPRINTF("local_hproc_id = %d\n", heca.local_hproc_id);
    printf("local_hproc_id= %d\n", heca.local_hproc_id);

    char masterinfo_option[128];
    get_param(masterinfo_option, "master", sizeof(masterinfo_option), optarg);

    char l_buf[200];
    const char *q = masterinfo_option;
 
    q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
    q++;
    char ip[100];
    strcpy(ip, l_buf);
    DPRINTF("ip is : %s\n",ip);

    // Parse rdma port
    q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
    q++;
    int port = strtoull(l_buf, NULL, 10);
    if (port) /* FIXME: port not needed */
        DPRINTF("port is : %d\n",port);

    // Parse tcp port
    q = get_opt_name(l_buf, sizeof(l_buf), q, ':');
    q++;
    int tcp_port = strtoull(l_buf, NULL, 10);
    DPRINTF("tcp port: %d\n", tcp_port);

    bzero((char*) &heca.master_addr, sizeof(heca.master_addr));
    heca.master_addr.sin_family = AF_INET;
    heca.master_addr.sin_port = htons(tcp_port);
    heca.master_addr.sin_addr.s_addr = inet_addr(ip);
    printf("leaving...\n");
}

void heca_migrate_dest_init(const char* dest_ip, const char* source_ip)
{
    heca_config();
    heca.is_enabled = true;
    heca.hspace_id = 1;          // only need 1 for live migration (LM)
    heca.local_hproc_id = 1;    // master node is 1
    heca.hproc_count = 2;       // only master and client required for LM
    heca.mr_count = 1;        // only need 1 memory region for LM

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

    heca.hproc_array = calloc(heca.hproc_count, sizeof(struct hecaioc_hproc));
    heca.hproc_array[0] = dst_hproc;
    heca.hproc_array[1] = src_hproc;

    heca.mr_array = calloc(heca.mr_count, sizeof(struct hecaioc_hmr));
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

    heca.mr_array[0].addr = ram_ptr; // only one memory region required for LM
    heca.mr_array[0].sz = ram_sz;

    DPRINTF("initializing heca master\n");

    //print_data_structures();
    heca.rdma_fd = heca_master_open(heca.hproc_count, 
            heca.hproc_array, heca.mr_count, heca.mr_array);

    if (heca.rdma_fd < 0) {
        DPRINTF("Error initializing master node\n");
        exit(1);
    }

    DPRINTF("Heca master node is ready..\n");
    //hspace_cleanup(fd); 
}

void heca_migrate_src_init(const char* uri, int precopy_time)
{
    heca_config();

    heca.is_enabled = true;
    heca.hspace_id = 1;         // only need 1 for live migration (LM)
    heca.local_hproc_id = 2;   // client node
    heca.hproc_count = 2;      // only master and client required for LM

    const char* dest_ip = ip_from_uri(uri);
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

    DPRINTF("initializing heca client node ...\n");
    
    heca.rdma_fd = heca_client_open(ram_ptr, ram_size, 
            heca.local_hproc_id, &heca.master_addr);

    if (heca.rdma_fd < 0 ) {
        DPRINTF("Error initializing client node\n");
        exit(1);
    }

    DPRINTF("Heca client node is ready..\n");
    //hspace_cleanup(fd); 
}

static const char* ip_from_uri(const char* uri) 
{
    char char_array_uri[256];

    char_array_uri[sizeof(char_array_uri) - 1] = 0;
    strncpy(char_array_uri, uri, sizeof(char_array_uri) - 1);

    char* ip = strtok(char_array_uri, ":"); // ip points to uri protocol, e.g. 'tcp'
    ip = strtok(NULL, ":");                 // ip now points to ip address

    return (const char*) ip;
}

static void heca_config(void)
{
    // read file .heca_config. Ideally, all configuration would be contained here.
    wordexp_t result;
    wordexp("~/.heca_config", &result, 0);
    const char* heca_conf_path = result.we_wordv[0];

    FILE *conf_file = fopen(heca_conf_path, "r");
    if (conf_file == NULL) {
        // use default port values
        heca.rdma_port = 4444;
        heca.tcp_sync_port = 4445;
    }

    if (conf_file && fscanf(conf_file, "RDMA_PORT=%d", &heca.rdma_port) < 1) {
        fprintf(stderr, "Couldn't read RDMA_PORT - defaulting to 4444\n");
        heca.rdma_port = 4444;
    };

    if (conf_file && fscanf(conf_file, "TCP_SYNC_PORT=%d", &heca.tcp_sync_port) < 1) {
        fprintf(stderr, "Couldn't read TCP_SYNC_PORT defaulting to 4445\n");
        heca.tcp_sync_port = 4445;
    };
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
    int i;
    int j;
    printf("hproc_array:\n");
    for (i = 0; i < heca.hproc_count; i++) {
        printf("{ .hspace_id = %d, .hproc_id = %d, .ip = %s, .port = %d}\n", 
            heca.hproc_array[i].hspace_id, heca.hproc_array[i].hproc_id, 
            inet_ntoa(heca.hproc_array[i].remote.sin_addr),
            ntohs(heca.hproc_array[i].remote.sin_port));
    }
    printf("mr_array:\n");
    for (i = 0; i < heca.mr_count; i++) {
        printf("{ .hspace_id = %d, .hmr_id = %d, .addr = %ld, .sz = %lld, .flags = %d, .hproc_ids = { ",
            heca.mr_array[i].hspace_id, heca.mr_array[i].hmr_id, 
            (unsigned long) heca.mr_array[i].addr, 
            (long long) heca.mr_array[i].sz, heca.mr_array[i].flags);
        j = 0;
        while(heca.mr_array[i].hproc_ids[j] != 0) {
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
    unsigned long unmap_offset = -1; // -1 is reset value
    int count = 0;

    for (i = 0; i < bitmap_size; i++) {
        if (bitmap[i] & 0x08) { 
            // page is dirty, flag start of dirty range
            count ++;

            if (unmap_offset == -1) 
                unmap_offset = i * TARGET_PAGE_SIZE;
            unmap_size += TARGET_PAGE_SIZE;

        } else if (unmap_size > 0) {
            // end of dirty range

            unmap_addr = (void*) (host_ram + unmap_offset);
            ret = heca_unmap_memory(unmap_addr, unmap_size);
            if (ret < 0) {
                return ret;
            }

            // reset 
            unmap_offset = -1;
            unmap_size = 0;
        }
    }
    if (unmap_size > 0) {
        // Last page was dirty but we have finished iterating over bitmap
        unmap_addr = (void*) (host_ram + unmap_offset);
        ret = heca_unmap_memory(unmap_addr, unmap_size);
        if (ret < 0) {

            return ret;
        }
    }
    qemu_add_vm_change_state_handler(heca_change_state_handler, NULL);
    return ret;
}

void heca_master_cmdline_init(const char* optarg)
{
    heca.is_enabled = true;
    heca.is_master = true;
    heca_gdb_stub();
    parse_heca_master_commandline(optarg);

    int i;
    for (i = 0; i < heca.mr_count; i++)
        heca.mr_array[i].flags |= UD_AUTO_UNMAP;
}

void heca_client_cmdline_init(const char* optarg)
{
    heca.is_enabled = true;
    heca.is_master = false;
    heca_gdb_stub();
    parse_heca_client_commandline(optarg);
}

void heca_init(void* ram_ptr, uint64_t ram_size)
{
    if (heca.is_master) {
        bool debug = true;
        if (debug) 
            print_data_structures();

        heca_assign_master_mem(ram_ptr, ram_size);

        // init heca
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


#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <netinet/in.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>

#include <libkern/OSMalloc.h>
#include <sys/kern_control.h>

#include "TestFilter.h"

static boolean_t initted = FALSE;
static long ctl_connected = 0;
static long packet_index = 0;

typedef enum PACKETPROCFLAGS {
    IN_DONE = 1,
    OUT_DONE = 2
} PACKETPROCFLAGS;

static OSMallocTag gOSMallocTag;

static boolean_t gFilterRegistered_ip4 = FALSE;
static boolean_t gUnregisterProc_ip4_started = FALSE;
static boolean_t gUnregisterProc_ip4_complete = FALSE;
static boolean_t gKernCtlRegistered = FALSE;

static lck_mtx_t *gmutex = NULL;
static lck_mtx_t *gmutex_packet = NULL;
static lck_grp_t *gmutex_grp = NULL;

static mbuf_tag_id_t gidtag;

struct tl_cb {
    TAILQ_ENTRY(tl_cb)  t_link;
    kern_ctl_ref        t_ref;
    u_int32_t           t_unit;
    u_int32_t           magic;
    boolean_t           t_connected;
    pid_t               t_uid;
};

typedef struct _filter_cookie {
    kern_ctl_ref        ctl_ref;
    u_int32_t           ctl_unit;
    
} filter_cookie;

static kern_ctl_ref gctl_ref;

TAILQ_HEAD(tl_cb_list, tl_cb);
static struct tl_cb_list tl_cb_list;

void send_notification(filter_cookie *f_cookie, FilterNotification *notification) {
    lck_mtx_lock(gmutex_packet);
    notification->packetId = packet_index;
    packet_index++;
    int retval = ctl_enqueuedata(f_cookie->ctl_ref, f_cookie->ctl_unit, notification, sizeof(FilterNotification), CTL_DATA_EOR);
    lck_mtx_unlock(gmutex_packet);
    
    if (retval != 0) {
        printf("ctl_enqueuedata failed %d\n", retval);
    }
}

struct tl_cb *find_ctl(pid_t uid) {
    struct tl_cb *tl_cb;
    TAILQ_FOREACH(tl_cb, &tl_cb_list, t_link) {
        if (tl_cb->t_connected == FALSE) {
            continue;
        }
        
        if (tl_cb->t_unit == FILTER_INVALID_UNIT) {
            continue;
        }
        
        if (tl_cb->t_uid == uid) {
            return tl_cb;
        }
    }
    return NULL;
}

struct tl_cb *find_ctl_by_ref(kern_ctl_ref ref) {
    struct tl_cb *tl_cb;
    TAILQ_FOREACH(tl_cb, &tl_cb_list, t_link) {
        if (tl_cb->t_connected == FALSE) {
            continue;
        }
        
        if (tl_cb->t_unit == FILTER_INVALID_UNIT) {
            continue;
        }
        
        if (tl_cb->t_ref == ref) {
            return tl_cb;
        }
    }
    return NULL;
}

filter_cookie *get_filter_cookie(void *cookie) {
    return (filter_cookie*)cookie;
}

errno_t prepend_mbuf_hdr(mbuf_t *data, size_t pkt_len) {
    mbuf_t new_hdr;
    errno_t status;
    
    status = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &new_hdr);
    if (KERN_SUCCESS == status) {
        mbuf_setnext(new_hdr, *data);
        mbuf_setnextpkt(new_hdr, mbuf_nextpkt(*data));
        mbuf_pkthdr_setlen(new_hdr, pkt_len);
        mbuf_setlen(new_hdr, 0);
        
        mbuf_pkthdr_setrcvif(*data, NULL);
        
        *data = new_hdr;
    }
    return status;
}

int check_tag(mbuf_t *m, mbuf_tag_id_t module_id, mbuf_tag_type_t tag_type, PACKETPROCFLAGS value) {
    errno_t status;
    int *tag_ref;
    size_t len;
    
    status = mbuf_tag_find(*m, module_id, tag_type, &len, (void**)&tag_ref);
    if ((status == 0) && (*tag_ref == value) && (len == sizeof(value))) {
        return 1;
    }
    
    return 0;
}

errno_t set_tag(mbuf_t *data, mbuf_tag_id_t id_tag, mbuf_tag_type_t tag_type, PACKETPROCFLAGS value) {
    errno_t status;
    int *tag_ref = NULL;
    size_t len;
    
    assert(data);
    status = mbuf_tag_find(*data, id_tag, tag_type, &len, (void*)&tag_ref);
    if (status != 0) {
        status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
        if (status == 0) {
            *tag_ref = value;
        } else if (status == EINVAL) {
            mbuf_flags_t    flags;
            flags = mbuf_flags(*data);
            if ((flags & MBUF_PKTHDR) == 0) {
                mbuf_t m = *data;
                size_t totalbytes = 0;
                
                printf("mbuf_t missing MBUF_PKTHDR bit\n");
                
                while (m) {
                    totalbytes += mbuf_len(m);
                    m = mbuf_next(m);
                }
                status = prepend_mbuf_hdr(data, totalbytes);
                if (status == KERN_SUCCESS) {
                    status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
                    if (status) {
                        printf("mbuf_tag_allocate failed a second time, status was %d\n", status);
                    }
                }
            }
        }
        else {
            printf("mbuf_tag_allocate failed, status was %d\n", status);
        }
    }
    return status;
}

void tl_unregistered_fn_ip4(sflt_handle handle) {
    gUnregisterProc_ip4_complete = TRUE;
    gFilterRegistered_ip4 = FALSE;
    printf("tl_unregistered_fn_ip4\n");
}

errno_t tl_attach_fn(void **cookie, socket_t so) {
    errno_t result = 0;
    
    lck_mtx_lock(gmutex);
    
    pid_t uid = kauth_getuid();
    struct tl_cb *tl_cb = find_ctl(uid);
    
    printf("uid: %d", uid);
    if (!tl_cb) {
        printf("!tl_cb\n");
        lck_mtx_unlock(gmutex);
        return ENXIO;
    }
    
    filter_cookie *f_cookie = (filter_cookie *)OSMalloc(sizeof(filter_cookie), gOSMallocTag);
    if (f_cookie == NULL) {
        printf("!f_cookie\n");
        lck_mtx_unlock(gmutex);
        return ENOBUFS;
    }
    
    f_cookie->ctl_ref = tl_cb->t_ref;
    f_cookie->ctl_unit = tl_cb->t_unit;
    *(filter_cookie**)cookie = f_cookie;
    
    lck_mtx_unlock(gmutex);
    
    return result;
}

errno_t tl_attach_fn_ip4(void **cookie, socket_t so) {
    errno_t result = 0;
    
    result = tl_attach_fn(cookie, so);
    
    return result;
}

void tl_detach_fn4(void *cookie, socket_t so) {
    if (!cookie) return;
    
    OSFree(cookie, sizeof(filter_cookie), gOSMallocTag);
}

errno_t tl_data_fn(void *cookie, socket_t so, const struct sockaddr *addr, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags, FilterSocketDataDirection direction) {
    errno_t result = 0;
    
    if (check_tag(data, gidtag, FILTER_TAG_TYPE, direction == FilterSocketDataDirectionIn ? IN_DONE : OUT_DONE)) {
        return result;
    }
    
    if (!cookie) return result;
    
    filter_cookie *f_cookie = get_filter_cookie(cookie);
    
    uint32_t data_size = (uint32_t)mbuf_pkthdr_len(*data);
    uint32_t offset = 0;
    
    printf("tl_data_ft: %d", data_size);
    
    while (offset < data_size) {
        FilterNotification notification;
        
        if (direction == FilterSocketDataDirectionIn) {
            notification.event = FilterEventDataIn;
        } else {
            notification.event = FilterEventDataOut;
        }
        notification.socketId = (uint64_t)so;
        notification.inputoutput.dataSize = min(data_size - offset, sizeof(notification.inputoutput.data));
        
        mbuf_copydata(*data, offset, notification.inputoutput.dataSize, notification.inputoutput.data);
        offset += notification.inputoutput.dataSize;
        
        send_notification(f_cookie, &notification);
    }
    
    result = EJUSTRETURN;
    
    if (result == EJUSTRETURN) {
        mbuf_freem(*data);
        
        if (control != NULL && *control != NULL)
            mbuf_freem(*control);
    }
    
    return result;
}

errno_t tl_data_in_fn(void *cookie, socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags) {
    return tl_data_fn(cookie, so, from, data, control, flags, FilterSocketDataDirectionIn);
}

errno_t tl_data_out_fn(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags) {
    return tl_data_fn(cookie, so, to, data, control, flags, FilterSocketDataDirectionOut);
}

errno_t add_ctl_unit(kern_ctl_ref ctl_ref, u_int32_t unit, struct tl_cb **ret_tl_cb) {
    struct tl_cb *tl_cb = NULL;
    errno_t result = 0;
    
    tl_cb = (struct tl_cb *)OSMalloc(sizeof (struct tl_cb), gOSMallocTag);
    if (tl_cb == NULL) {
        printf("malloc error occurred \n");
        result = ENOMEM;
    }
    
    if (result == 0) {
        bzero(tl_cb, sizeof (struct tl_cb));
        
        tl_cb->t_unit = unit;
        tl_cb->t_ref = ctl_ref;
        tl_cb->t_uid = -1;
        *ret_tl_cb = tl_cb;
        
        lck_mtx_lock(gmutex);
        
        TAILQ_INSERT_TAIL(&tl_cb_list, tl_cb, t_link);
        
        lck_mtx_unlock(gmutex);
    }
    
    return result;
}

errno_t ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo) {
    errno_t result = 0;
    
    struct tl_cb *tl_cb;
    
    result = add_ctl_unit(ctl_ref, sac->sc_unit, &tl_cb);
    if (result == 0) {
        printf("ctl_connect\n");
        *unitinfo = tl_cb;
        tl_cb->t_connected = TRUE;
        tl_cb->magic = ENTRY_MAGIC;
        ctl_connected++;
    }
    
    return result;
}

errno_t del_ctl_unit_locked(struct tl_cb * tl_cb) {
    printf("will unregister unit %d\n", tl_cb->t_unit);
    
    TAILQ_REMOVE(&tl_cb_list, tl_cb, t_link);
    OSFree(tl_cb, sizeof(struct tl_cb), gOSMallocTag);
    ctl_connected--;
    
    return 0;
}

errno_t del_ctl_unit(struct tl_cb * tl_cb) {
    errno_t error;
    
    lck_mtx_lock(gmutex);
    
    error = del_ctl_unit_locked(tl_cb);
    
    lck_mtx_unlock(gmutex);
    
    return error;
}

errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo) {
    struct tl_cb *tl_cb = (struct tl_cb *) unitinfo;
    
    printf("ctl_disconnect\n");
    
    if (tl_cb) {
        del_ctl_unit(tl_cb);
    }
    
    return 0;
}

errno_t ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len) {
    errno_t result = 0;
    
    return result;
}

errno_t ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len) {
    errno_t result = 0;
    
    lck_mtx_lock(gmutex);
    
    struct tl_cb *tl_cb = find_ctl_by_ref(ctl_ref);
    if (!tl_cb) {
        printf("!tl_cb\n");
        lck_mtx_unlock(gmutex);
        return ENXIO;
    }
    
    int value;
    switch (opt) {
        case FILTER_UID:
            if (len < sizeof(value)) {
                result = EINVAL;
                break;
            }
            value = *(int *)data;
            
            tl_cb->t_uid = value;
            break;
    }
    
    lck_mtx_unlock(gmutex);
    
    return result;
}

errno_t ctl_send(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags) {
    printf("ctl_send");
    errno_t error = 0;
    
    if (m == NULL || mbuf_pkthdr_len(m) != sizeof(FilterClientResponse)) {
        mbuf_freem(m);
        return error;
    }
    
    FilterClientResponse response;
    mbuf_copydata(m, 0, sizeof(response), &response);
    
    mbuf_t data;
    error = mbuf_allocpacket(MBUF_WAITOK, response.dataSize, NULL, &data);
    if (error) {
        mbuf_freem(m);
        return error;
    }
    
    error = mbuf_copyback(data, 0, response.dataSize, response.data, MBUF_WAITOK);
    if (error) {
        mbuf_freem(m);
        mbuf_freem(data);
        return error;
    }
    
    error = set_tag(&data, gidtag, FILTER_TAG_TYPE, response.direction == FilterSocketDataDirectionIn ? IN_DONE : OUT_DONE);
    if (error) {
        mbuf_freem(m);
        mbuf_freem(data);
        return error;
    }
    
    if (response.direction == FilterSocketDataDirectionIn) {
        error = sock_inject_data_in((socket_t)response.socketId, NULL, data, NULL, 0);
    } else {
        error = sock_inject_data_out((socket_t)response.socketId, NULL, data, NULL, 0);
    }
    
    if (error && response.direction == FilterSocketDataDirectionIn) {
        //mbuf_freem(data);
    }
    
    mbuf_freem(m);
    return error;
}

static struct sflt_filter TLsflt_filter_ip4 = {
    FILTER_HANDLE_IP4,
    SFLT_GLOBAL,
    MYBUNDLEID,
    tl_unregistered_fn_ip4,
    tl_attach_fn_ip4,
    tl_detach_fn4,
    NULL,
    NULL,
    NULL,
    tl_data_in_fn,
    tl_data_out_fn,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static struct kern_ctl_reg gctl_reg = {
    MYBUNDLEID,
    0,
    0,
    CTL_FLAG_PRIVILEGED,
    (1024 * 1024),
    (1024 * 1024),
    ctl_connect,
    ctl_disconnect,
    ctl_send,
    ctl_set,
    ctl_get
};

errno_t del_all_ctl_unit(void) {
    errno_t error = 0;
    
    if (gKernCtlRegistered) {
        error = ctl_deregister(gctl_ref);
        if (error == 0) {
            gKernCtlRegistered = FALSE;
        }
    }
    return error;
}

errno_t alloc_locks(void) {
    errno_t result = 0;
    gmutex_grp = lck_grp_alloc_init(MYBUNDLEID, LCK_GRP_ATTR_NULL);
    if (gmutex_grp == NULL) {
        printf("error calling lck_grp_alloc_init\n");
        result = ENOMEM;
    }
    
    if (result == 0) {
        gmutex = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
        if (gmutex == NULL) {
            printf("error calling lck_mtx_alloc_init\n");
            result = ENOMEM;
        }
        
        gmutex_packet = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
        if (gmutex_packet == NULL) {
            printf("error calling lck_mtx_alloc_init\n");
            result = ENOMEM;
        }
    }
    
    return result;
}

void free_locks(void) {
    if (gmutex) {
        lck_mtx_free(gmutex, gmutex_grp);
        gmutex = NULL;
    }
    
    if (gmutex_packet) {
        lck_mtx_free(gmutex_packet, gmutex_grp);
        gmutex_packet = NULL;
    }
    
    if (gmutex_grp) {
        lck_grp_free(gmutex_grp);
        gmutex_grp = NULL;
    }
}

kern_return_t TestFilter_start(kmod_info_t *ki, void *data) {
    kern_return_t retval = 0;
    
    if (initted) return 0;
    
    retval = alloc_locks();
    if (retval) goto bail;
    
    TAILQ_INIT(&tl_cb_list);
    
    gOSMallocTag = OSMalloc_Tagalloc(MYBUNDLEID, OSMT_DEFAULT);
    if (gOSMallocTag == NULL) goto bail;
    
    retval = mbuf_tag_id_find(MYBUNDLEID , &gidtag);
    if (retval != 0) {
        printf("mbuf_tag_id_find returned error %d\n", retval);
        goto bail;
    }
    
    retval = sflt_register(&TLsflt_filter_ip4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    printf("sflt_register returned result %d for ip4 filter.\n", retval);
    if (retval == 0) {
        gFilterRegistered_ip4 = TRUE;
    } else {
        goto bail;
    }
    
    retval = ctl_register(&gctl_reg, &gctl_ref);
    if (retval == 0) {
        printf("ctl_register id 0x%x, ref 0x%x \n", gctl_reg.ctl_id, (unsigned int)gctl_ref);
        gKernCtlRegistered = TRUE;
    } else {
        printf("ctl_register returned error %d\n", retval);
        goto bail;
    }
    
    initted = TRUE;
    
    printf("TestFilter_start returning %d\n", retval);
    
    return KERN_SUCCESS;
    
bail:
    if (gFilterRegistered_ip4) {
        sflt_unregister(FILTER_HANDLE_IP4);
    }
    
    if (gFilterRegistered_ip4) {
        del_all_ctl_unit();
        gFilterRegistered_ip4 = FALSE;
    }
    
    free_locks();
    printf("TestFilter_start returning %d\n", KERN_FAILURE);
    return KERN_FAILURE;
}

kern_return_t TestFilter_stop(kmod_info_t *ki, void *data) {
    kern_return_t retval;
    
    if (!gFilterRegistered_ip4) return KERN_SUCCESS;
    
    if (!initted) return KERN_SUCCESS;
    
    if (ctl_connected) {
        printf("still connected to a control socket - quit control process\n");
    }
    
    retval = del_all_ctl_unit();
    printf("TestFilter_stop - del_all_ctl_unit returned %d\n", retval);
    
    if (retval == 0) {
        if (gUnregisterProc_ip4_started == FALSE) {
            retval = sflt_unregister(FILTER_HANDLE_IP4);
            if (retval != 0) {
                printf("TestFilter_stop: sflt_unregister failed for ip4 %d\n", retval);
            } else {
                gUnregisterProc_ip4_started = TRUE;
            }
        }
        
        if (gUnregisterProc_ip4_complete) {
            retval = KERN_SUCCESS;
        } else {
            printf("TestFilter_stop: again\n");
            retval = KERN_FAILURE;
        }
    }
    
    if (retval == KERN_SUCCESS) {
        free_locks();
        if (gOSMallocTag) {
            OSMalloc_Tagfree(gOSMallocTag);
            gOSMallocTag = NULL;
        }
    }
    
bail:
    printf("TestFilter_stop end %d\n", retval);
    return retval;
}

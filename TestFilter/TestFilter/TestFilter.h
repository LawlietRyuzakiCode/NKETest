#ifndef testfilter_h
#define testfilter_h

#define FILTER_HANDLE_IP4       0xBABABABA
#define ENTRY_MAGIC             0xDDCCBBAA
#define FILTER_TAG_TYPE         42
#define DATA_SIZE               1500

#define FILTER_UID              1

#define MYBUNDLEID              "com.test.kext.TestFilter"
#define FILTER_INVALID_UNIT     0xFFFFFFFF

typedef enum _FilterEvent {
    FilterEventUnknown = 0x0,
    FilterEventDataIn,
    FilterEventDataOut,
    
    FilterEventMax = 0xFFFFFFFF
} FilterEvent;

typedef enum _FilterSocketDataDirection {
    FilterSocketDataDirectionOut = 1,
    FilterSocketDataDirectionIn,
    
    FilterSocketDataDirectionMax = 0xFFFFFFFF
} FilterSocketDataDirection;

typedef struct _FilterEventIoData {
    uint32_t    dataSize;
    uint8_t     data[DATA_SIZE];
} FilterEventIoData;

typedef struct _FilterNotification {
    uint64_t            socketId;
    size_t              packetId;
    FilterEvent         event;
    
    FilterEventIoData   inputoutput;
} FilterNotification;

typedef struct _FilterClientResponse {
    uint64_t                    socketId;
    
    FilterSocketDataDirection   direction;
    uint32_t                    dataSize;
    uint8_t                     data[DATA_SIZE];
} FilterClientResponse;

#endif


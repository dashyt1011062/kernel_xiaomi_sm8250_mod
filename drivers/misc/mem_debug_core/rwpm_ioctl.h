#ifndef RWPM_IOCTL_H_
#define RWPM_IOCTL_H_

#include <linux/types.h>

#pragma pack(push,1)
struct ioctl_request {
    char     cmd;
    uint64_t param1;
    uint64_t param2;
    uint64_t param3;
    uint64_t buf_size;
};
#pragma pack(pop)

#endif /* RWPM_IOCTL_H_ */

#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/socket.h>

#include "../TestFilter/TestFilter/TestFilter.h"
#include "vproc_priv.h"

int main() {
    int s = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (s < 0) {
        throw std::runtime_error("");
    }

    struct ctl_info ctlInfo;
    struct sockaddr_ctl sc;

    bzero(&ctlInfo, sizeof(struct ctl_info));
    strcpy(ctlInfo.ctl_name, MYBUNDLEID);
    if (ioctl(s, CTLIOCGINFO, &ctlInfo) == -1) {
        throw std::runtime_error("");
    }

    bzero(&sc, sizeof(struct sockaddr_ctl));
    sc.sc_len = sizeof(struct sockaddr_ctl);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = SYSPROTO_CONTROL;
    sc.sc_id = ctlInfo.ctl_id;
    sc.sc_unit = 0;

    if (::connect(s, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
        throw std::runtime_error("");
    }

    int64_t uid = -1;
    vproc_err_t verr = vproc_swap_integer(nullptr, VPROC_GSK_MGR_UID, nullptr, &uid);
    auto userId = static_cast<pid_t>(uid);

    int on = 1;
    if (setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on)) == -1) {
        throw std::runtime_error("");
    }

    if (setsockopt(s, SYSPROTO_CONTROL, FILTER_UID, &userId, sizeof(userId)) == -1) {
        throw std::runtime_error("");
    }

    FilterNotification notification;
    while (recv(s, &notification, sizeof(FilterNotification), 0) == sizeof(FilterNotification)) {
        if (notification.event == FilterEventDataIn || notification.event == FilterEventDataOut) {
            FilterClientResponse response;
            response.socketId = notification.socketId;
            response.direction = (notification.event == FilterEventDataIn) ? FilterSocketDataDirectionIn : FilterSocketDataDirectionOut;
            response.dataSize = notification.inputoutput.dataSize;
            memcpy(response.data, notification.inputoutput.data, notification.inputoutput.dataSize);
            send(s, &response, sizeof(response), 0);
        }
    }
}
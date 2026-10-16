#ifndef DEVICEINFO_STASH_H
#define DEVICEINFO_STASH_H

#include <string>
#include <vector>
#include <flow/flow_stash.h>

#define STASH_DEVICEINFO "deviceinfo"

class DeviceInfoStash : public snort::StashGenericObject
{
public:
    std::vector<std::string> deviceinfo;

    DeviceInfoStash() = default;
    ~DeviceInfoStash() override = default;
};

#endif

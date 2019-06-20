#include <string>
#include <vector>
#include <netaddress.h>

#ifndef BITCOIN_NET_PERMISSIONS_H
#define BITCOIN_NET_PERMISSIONS_H
enum CNetPermissionFlags
{
    PF_NONE = 0,
    // Can query bloomfilter even if -peerbloomfilters is false
    PF_BLOOMFILTER = (1U << 1),
    // Always relay transactions, even if already in mempool or rejected from policy
    PF_FORCERELAY = (1U << 2),
    // Relay and accept transactions from the peer even if -blocksonly is true
    PF_RELAY = (1U << 3),
    // Can't be banned for misbehavior
    PF_NOBAN = (1U << 4),
    // Can query the mempool
    PF_MEMPOOL = (1U << 5),

    // True if the user did not specifically set fine grained permissions
    PF_ISDEFAULT = (1U << 31),
    PF_DEFAULT = PF_NOBAN | PF_MEMPOOL,
    PF_ALL = PF_BLOOMFILTER | PF_FORCERELAY | PF_RELAY | PF_NOBAN | PF_MEMPOOL,
};
class CNetPermissions
{
public:
    CNetPermissionFlags flags;
    static std::vector<std::string> ToStrings(CNetPermissionFlags flags);
};
class CNetWhitebindPermissions : public CNetPermissions
{
public:
    static bool TryParse(const std::string str, CNetWhitebindPermissions* output, std::string* error);
    CService service;
};

class CNetWhitelistPermissions : public CNetPermissions
{
public:
    static bool TryParse(const std::string str, CNetWhitelistPermissions* output, std::string* error);
    CSubNet subnet;
};

#endif // BITCOIN_NET_PERMISSIONS_H
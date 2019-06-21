#include <net_permissions.h>
#include <util/system.h>
#include <netbase.h>

bool TryParsePermissionFlags(const std::string str, CNetPermissionFlags* output, size_t* readen, std::string* error)
{
    CNetPermissionFlags flags = PF_NONE;
    const auto permissionSeparator = str.find('@');
    if (permissionSeparator == std::string::npos)
    {
        flags = static_cast<CNetPermissionFlags>(PF_DEFAULT | PF_ISDEFAULT);
    }
    else
    {
        size_t offset = 0;
        const auto permissions = str.substr(0, permissionSeparator);
        while (offset < permissions.length())
        {
            const auto permissionSeparator = permissions.find(',', offset);
            int len = permissionSeparator == std::string::npos ? permissions.length() - offset : permissionSeparator - offset;
            auto permission = permissions.substr(offset, len);
            offset += len;
            if (permissionSeparator != std::string::npos)
                offset += 1;
            if (permission == "bloomfilter" || permission == "bloom")
            {
                flags = static_cast<CNetPermissionFlags>(flags | PF_BLOOMFILTER);
            }
            else if (permission == "noban")
            {
                flags = static_cast<CNetPermissionFlags>(flags | PF_NOBAN);
            }
            else if (permission == "forcerelay")
            {
                flags = static_cast<CNetPermissionFlags>(flags | PF_FORCERELAY);
            }
            else if (permission == "mempool")
            {
                flags = static_cast<CNetPermissionFlags>(flags | PF_MEMPOOL);
            }
            else if (permission == "all")
            {
                flags = PF_ALL;
            }
            else if (permission == "relay")
            {
                flags = static_cast<CNetPermissionFlags>(flags | PF_RELAY);
            }
            else if (permission.length() == 0)
            {
                // Allow empty entries
            }
            else
            {
                if (error != NULL)
                {
                    *error = strprintf(_("Invalid P2P permission: '%s'"), permission);
                }
                return false;
            }
        }
    }
    if (output != NULL)
        *output = flags;
    if (readen != NULL)
    {
        *readen = permissionSeparator == std::string::npos ? 0 : permissionSeparator + 1;
    }
    if (error != NULL)
        *error = "";
    return true;
}

std::vector<std::string> CNetPermissions::ToStrings(CNetPermissionFlags flags)
{
    std::vector<std::string> strings;
    if ((flags & PF_BLOOMFILTER) != 0)
        strings.push_back("bloomfilter");
    if ((flags & PF_NOBAN) != 0)
        strings.push_back("noban");
    if ((flags & PF_FORCERELAY) != 0)
        strings.push_back("forcerelay");
    if ((flags & PF_RELAY) != 0)
        strings.push_back("relay");
    if ((flags & PF_MEMPOOL) != 0)
        strings.push_back("mempool");
    return strings;
}

bool CNetWhitebindPermissions::TryParse(const std::string str, CNetWhitebindPermissions* output, std::string* error)
{
    CNetPermissionFlags flags;
    size_t offset;
    if (!TryParsePermissionFlags(str, &flags, &offset, error))
        return false;

    const std::string strBind = str.substr(offset);
    CService addrBind;
    if (!Lookup(strBind.c_str(), addrBind, 0, false)) {
        if (error != NULL)
        {
            *error = strprintf(_("Cannot resolve -whitebind address: '%s'"), strBind);
        }
        return false;
    }
    if (addrBind.GetPort() == 0) {
        if (error != NULL)
        {
            *error = strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind);
        }
        return false;
    }

    if (output != NULL)
    {
        output->flags = flags;
        output->service = addrBind;
    }
    if (error != NULL)
        *error = "";
    return true;
}

bool CNetWhitelistPermissions::TryParse(const std::string str, CNetWhitelistPermissions* output, std::string* error)
{
    CNetPermissionFlags flags;
    size_t offset;
    if (!TryParsePermissionFlags(str, &flags, &offset, error))
        return false;

    const std::string net = str.substr(offset);
    CSubNet subnet;
    LookupSubNet(net.c_str(), subnet);
    if (!subnet.IsValid())
    {
        if (error != NULL)
        {
            *error = strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net);
        }
        return false;
    }

    if (output != NULL)
    {
        output->flags = flags;
        output->subnet = subnet;
    }
    if (error != NULL)
        *error = "";
    return true;
}

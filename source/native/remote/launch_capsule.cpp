#include "launch_capsule.hpp"
#include "ipc_wire.hpp"
#include <algorithm>
#include <stdexcept>

namespace remote {
void validate_launch_capsule(const LaunchCapsule& value,std::uint64_t now){
    const auto& spec=value.spec;
    const auto okay=value.bytes==sizeof(value) && value.format==1 && (value.role==1 || value.role==2) && spec.bytes==sizeof(spec) && spec.format==1 && spec.reserved==0 && spec.can_control<=1 && (!spec.administrator || spec.can_control) &&
        spec.wts_session>0 && spec.administrator<=1 && spec.authentication && spec.logon_time && spec.consent_filetime && spec.transport &&
        ipc::valid_consent(spec.consent_tick_deadline,now) &&
        value.parent_process && value.parent_query_token && value.parent_created && value.parent_pid>4 && value.stop && value.frames.at(0) && value.frames.at(1) && value.frames.at(0)!=value.frames.at(1) &&
        std::find(std::begin(spec.user_sid),std::end(spec.user_sid),L'\0')!=std::end(spec.user_sid) && spec.user_sid[0]!=0 &&
        std::any_of(std::begin(spec.session),std::end(spec.session),[](auto byte){return byte!=0;});
    if(!okay)throw std::invalid_argument("launch_capsule_rejected");
}
}
